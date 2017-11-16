package api

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"time"
	"database/sql"
//	"strconv"
	"strings"

//	_ "github.com/bmizerany/pq"
	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/brocaar/lora-app-server/internal2/common"
	"github.com/brocaar/lora-app-server/internal2/handler"
	"github.com/brocaar/lora-app-server/internal2/storage"
	"github.com/brocaar/loraserver/api/as"
	"github.com/brocaar/lorawan"
	
)

// ApplicationServerAPI implements the as.ApplicationServerServer interface.
type ApplicationServerAPI struct {
	ctx common.Context
}

// NewApplicationServerAPI returns a new ApplicationServerAPI.
func NewApplicationServerAPI(ctx common.Context) *ApplicationServerAPI {
	return &ApplicationServerAPI{
		ctx: ctx,
	}
}

// JoinRequest handles a join-request.
func (a *ApplicationServerAPI) JoinRequest(ctx context.Context, req *as.JoinRequestRequest) (*as.JoinRequestResponse, error) {
	var phy lorawan.PHYPayload

	if err := phy.UnmarshalBinary(req.PhyPayload); err != nil {
		log.Errorf("unmarshal join-request PHYPayload error: %s", err)
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}

	jrPL, ok := phy.MACPayload.(*lorawan.JoinRequestPayload)
	if !ok {
		log.Errorf("join-request PHYPayload does not contain a JoinRequestPayload")
		return nil, grpc.Errorf(codes.InvalidArgument, "PHYPayload does not contain a JoinRequestPayload")
	}

	var netID lorawan.NetID
	var devAddr lorawan.DevAddr

	copy(netID[:], req.NetID)
	copy(devAddr[:], req.DevAddr)

	// get the node from the db and validate the AppEUI
	node, err := storage.GetNode(a.ctx.DB, jrPL.DevEUI)
	if err != nil {
		log.WithFields(log.Fields{
			"dev_eui": jrPL.DevEUI,
		}).Errorf("join-request node does not exist")
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}
	if node.AppEUI != jrPL.AppEUI {
		log.WithFields(log.Fields{
			"dev_eui":          node.DevEUI,
			"expected_app_eui": node.AppEUI,
			"request_app_eui":  jrPL.AppEUI,
		}).Error("join-request DevEUI exists, but with a different AppEUI")
		return nil, grpc.Errorf(codes.Unknown, "DevEUI exists, but with a different AppEUI")
	}

	// validate MIC
	ok, err = phy.ValidateMIC(node.AppKey)
	if err != nil {
		log.WithFields(log.Fields{
			"dev_eui": node.DevEUI,
			"app_eui": node.AppEUI,
		}).Errorf("join-request validate mic error: %s", err)
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}
	if !ok {
		log.WithFields(log.Fields{
			"dev_eui": node.DevEUI,
			"app_eui": node.AppEUI,
			"mic":     phy.MIC,
		}).Error("join-request invalid mic")
		return nil, grpc.Errorf(codes.InvalidArgument, "invalid MIC")
	}

	// validate that the DevNonce hasn't been used before
	if !node.ValidateDevNonce(jrPL.DevNonce) {
		log.WithFields(log.Fields{
			"dev_eui":   node.DevEUI,
			"app_eui":   node.AppEUI,
			"dev_nonce": jrPL.DevNonce,
		}).Error("join-request DevNonce has already been used")
		return nil, grpc.Errorf(codes.InvalidArgument, "DevNonce has already been used")
	}

	// get app nonce
	appNonce, err := getAppNonce()
	if err != nil {
		log.Errorf("get AppNone error: %s", err)
		return nil, grpc.Errorf(codes.Unknown, "get AppNonce error: %s", err)
	}

	// get the (optional) CFList
	cFList, err := storage.GetCFListForNode(a.ctx.DB, node)
	if err != nil {
		log.WithFields(log.Fields{
			"dev_eui": node.DevEUI,
			"app_eui": node.AppEUI,
		}).Errorf("join-request get CFList error: %s", err)
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	// get keys
	nwkSKey, err := getNwkSKey(node.AppKey, netID, appNonce, jrPL.DevNonce)
	if err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}
	appSKey, err := getAppSKey(node.AppKey, netID, appNonce, jrPL.DevNonce)
	if err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	// update the node
	node.DevAddr = devAddr
	node.NwkSKey = nwkSKey
	node.AppSKey = appSKey
	if err = storage.UpdateNode(a.ctx.DB, node); err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	// construct response
	jaPHY := lorawan.PHYPayload{
		MHDR: lorawan.MHDR{
			MType: lorawan.JoinAccept,
			Major: lorawan.LoRaWANR1,
		},
		MACPayload: &lorawan.JoinAcceptPayload{
			AppNonce: appNonce,
			NetID:    netID,
			DevAddr:  devAddr,
			RXDelay:  node.RXDelay,
			DLSettings: lorawan.DLSettings{
				RX2DataRate: uint8(node.RX2DR),
				RX1DROffset: node.RX1DROffset,
			},
			CFList: cFList,
		},
	}
	if err = jaPHY.SetMIC(node.AppKey); err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}
	if err = jaPHY.EncryptJoinAcceptPayload(node.AppKey); err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	b, err := jaPHY.MarshalBinary()
	if err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	resp := as.JoinRequestResponse{
		PhyPayload:  b,
		NwkSKey:     nwkSKey[:],
		RxDelay:     uint32(node.RXDelay),
		Rx1DROffset: uint32(node.RX1DROffset),
		RxWindow:    as.RXWindow(node.RXWindow),
		Rx2DR:       uint32(node.RX2DR),
		RelaxFCnt:   node.RelaxFCnt,
	}

	if cFList != nil {
		resp.CFList = cFList[:]
	}

	log.WithFields(log.Fields{
		"dev_eui":  node.DevEUI,
		"app_eui":  node.AppEUI,
		"dev_addr": node.DevAddr,
	}).Info("join-request accepted")

	err = a.ctx.Handler.SendJoinNotification(node.AppEUI, node.DevEUI, handler.JoinNotification{
		DevAddr: node.DevAddr,
		DevEUI:  node.DevEUI,
	})
	if err != nil {
		log.Error("send join notification to handler error: %s", err)
	}

	return &resp, nil
}

// HandleDataUp handles incoming (uplink) data.
func (a *ApplicationServerAPI) HandleDataUp(ctx context.Context, req *as.HandleDataUpRequest) (*as.HandleDataUpResponse, error) {
	if len(req.RxInfo) == 0 {
		return nil, grpc.Errorf(codes.InvalidArgument, "RxInfo must have length > 0")
	}

	var appEUI, devEUI lorawan.EUI64
	copy(appEUI[:], req.AppEUI)
	copy(devEUI[:], req.DevEUI)
	ts, err := time.Parse(time.RFC3339Nano, req.RxInfo[0].Time)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "could not parse RxInfo.Time: %s", err)
	}

	node, err := storage.GetNode(a.ctx.DB, devEUI)
	if err != nil {
		errStr := fmt.Sprintf("get node error: %s", err)
		log.WithField("dev_eui", devEUI).Error(errStr)
		return nil, grpc.Errorf(codes.Internal, errStr)
	}

	b, err := lorawan.EncryptFRMPayload(node.AppSKey, true, node.DevAddr, req.FCnt, req.Data)
	if err != nil {
		log.WithFields(log.Fields{
			"dev_eui": devEUI,
			"f_cnt":   req.FCnt,
		}).Errorf("decrypt payload error: %s", err)
		return nil, grpc.Errorf(codes.Internal, "decrypt payload error: %s", err)
	}

	pl := handler.DataUpPayload{
		DevEUI:       devEUI,
		Time:         ts,
		FPort:        uint8(req.FPort),
		GatewayCount: len(req.RxInfo),
		RSSI:         int(req.RxInfo[0].Rssi),
		Data:         b,
	}
/////////handle data ,save to database ,edit by li
	handleDataDb(devEUI[:],b)
	//save end
	err = a.ctx.Handler.SendDataUp(appEUI, devEUI, pl)
	if err != nil {
		errStr := fmt.Sprintf("send data up to mqtt handler error: %s", err)
		log.Error(errStr)
		return nil, grpc.Errorf(codes.Internal, errStr)
	}

	return &as.HandleDataUpResponse{}, nil
}


/**************************************
function name: handleDataDb(dev_eui []byte,data []byte)
function:      handleDataDb
***************************************/
func handleDataDb(dev_eui []byte,data []byte){
          var id int
          var room_id_table  int
          var dev_eui_table string
          var type_table string
	  var floor_id_table int
	  var temp_value_get float32
	  var humi_value_get float32
	  type_table=""
	  db,err:=sql.Open("postgres","user=loraserver password=dbpassword dbname=loraserver sslmode=disable")
	  _=err
 	  rows, err := db.Query("SELECT * FROM room_sensor") 
          for rows.Next() {
          var posx int
          var posy int
          err = rows.Scan(&id,&dev_eui_table,&type_table,&room_id_table,&posx,&posy,&floor_id_table)
          if strings.Contains(string(dev_eui_table),string(dev_eui[:])) == true {
            fmt.Printf("/***********find dev_eui*********/")
            break
          }
      }
        dev_eui_table=convertByteString(dev_eui)	
	timestamp := time.Now().Unix()
	tm := time.Unix(timestamp, 0)
	if strings.Contains(string(type_table),"tem_hum")==true && len(string(type_table))==len("tem_hum"){
	        fmt.Printf("/***********type ==  humi_temp*********/")
		//dev_eui_table=convertByteString(dev_eui)	
		stmt,err:=db.Prepare("INSERT INTO tem_hum_para(dev_eui,room_id,temp_value,humi_value,datetime,floor_id) VALUES($1,$2,$3,$4,$5,$6)")
	        temp_value_get=float32(float32(data[0])*10.0+float32(data[1])+float32(data[2])*0.100+float32(data[3])*0.010+0.001)
		humi_value_get=float32(float32(data[4])*10.0+float32(data[5])+float32(data[6])*0.100+float32(data[7])*0.010+0.001)
		res ,err :=stmt.Exec(dev_eui_table,room_id_table,temp_value_get,humi_value_get,tm.Format("2006-01-02 03:04:05 PM"),floor_id_table)
		if err==nil{
		   fmt.Printf("/***********Insert humi-temp OK!!!!*********/")
		}else{
		   panic(err)
		}
   		_=res
		_=err
	}
	if strings.Contains(string(type_table),"water")==true && len(string(type_table))==len("water"){	
		stmt,err:=db.Prepare("INSERT INTO water_para(dev_eui,room_id,water_status,datetime,floor_id) VALUES($1,$2,$3,$4,$5)")
		res ,err :=stmt.Exec(dev_eui_table,room_id_table,data[0],tm.Format("2006-01-02 03:04:05 PM"),floor_id_table)
		if data[0] == 0x01 {
			stmt, err = db.Prepare("update room_info set water_alarm_datetime=$1 where room_id=$2 and floor_id=$3")
			res, err = stmt.Exec(tm.Format("2006-01-02 03:04:05 PM"), room_id_table,floor_id_table)
		}
		_=res
		_=err
	}	
	if strings.Contains(string(type_table),"smoke")==true && len(string(type_table))==len("smoke"){	
		stmt,err:=db.Prepare("INSERT INTO smoke_para(dev_eui,room_id,smoke_status,datetime,floor_id) VALUES($1,$2,$3,$4,$5)")
		res ,err :=stmt.Exec(dev_eui_table,room_id_table,data[0],tm.Format("2006-01-02 03:04:05 PM"),floor_id_table)
		if data[0] == 0x01 {
			stmt, err = db.Prepare("update room_info set smoke_alarm_datetime=$1 where room_id=$2 and floor_id=$3")
			res, err = stmt.Exec(tm.Format("2006-01-02 03:04:05 PM"), room_id_table,floor_id_table)
		}
		_=res
		_=err
	}	
	if strings.Contains(string(type_table),"door")==true && len(string(type_table))==len("door"){
		fmt.Printf("/*************************type == door**********/")	
		stmt,err:=db.Prepare("INSERT INTO door_para(dev_eui,room_id,door_status,datetime,floor_id) VALUES($1,$2,$3,$4,$5)")
		res ,err :=stmt.Exec(dev_eui_table,room_id_table,data[0],tm.Format("2006-01-02 03:04:05 PM"),floor_id_table)
		if data[0] == 0x01 {
			stmt, err = db.Prepare("update room_info set door_alarm_datetime=$1 where room_id=$2 and floor_id=$3")
			res, err = stmt.Exec(tm.Format("2006-01-02 03:04:05 PM"), room_id_table,floor_id_table)
		}
		_=res
		_=err
	}

	db.Close()	
}

/******************
function name :  convertByteString (data []byte)(string)
function  :      convert []Byte	to string 
example:     [0x11,0xFe,0xAb]   return : "11feab"
*******************************/
func convertByteString (data []byte)(string){
          var charsave [64]byte
          var j int
          var temp byte
          j=0
          for i:=0;i<len(data);i++{
              temp=data[i]&0xf0>>4
              if temp>9{
              charsave[j]=temp+0x57
              j++
              }else{  
              charsave[j]=temp+0x30
              j++
              }
              temp=data[i]&0x0f
              if temp>9{
              charsave[j]=temp+0x57
              j++
              }else{
              charsave[j]=temp+0x30
              j++
              }
          }
          return string(charsave[0:j])
}
	


//func checkERR(err error){
//    if err != nil {
//        panic(err)
//    }
//}

// GetDataDown returns the first payload from the datadown queue.
func (a *ApplicationServerAPI) GetDataDown(ctx context.Context, req *as.GetDataDownRequest) (*as.GetDataDownResponse, error) {
	var devEUI lorawan.EUI64
	copy(devEUI[:], req.DevEUI)

	qi, err := storage.GetNextDownlinkQueueItem(a.ctx.DB, devEUI, int(req.MaxPayloadSize))
	if err != nil {
		errStr := fmt.Sprintf("get next downlink queue item error: %s", err)
		log.WithFields(log.Fields{
			"dev_eui":          devEUI,
			"max_payload_size": req.MaxPayloadSize,
		}).Error(errStr)
		return nil, grpc.Errorf(codes.Internal, errStr)
	}

	// the queue is empty
	if qi == nil {
		log.WithField("dev_eui", devEUI).Info("data-down item requested by network-server, but queue is empty")
		return &as.GetDataDownResponse{}, nil
	}

	node, err := storage.GetNode(a.ctx.DB, devEUI)
	if err != nil {
		errStr := fmt.Sprintf("get node error: %s", err)
		log.WithField("dev_eui", devEUI).Error(errStr)
		return nil, grpc.Errorf(codes.Internal, errStr)
	}

	b, err := lorawan.EncryptFRMPayload(node.AppSKey, false, node.DevAddr, req.FCnt, qi.Data)
	if err != nil {
		errStr := fmt.Sprintf("encrypt payload error: %s", err)
		log.WithFields(log.Fields{
			"dev_eui": devEUI,
			"id":      qi.ID,
		}).Error(errStr)
		return nil, grpc.Errorf(codes.Internal, errStr)
	}

	queueSize, err := storage.GetDownlinkQueueSize(a.ctx.DB, devEUI)
	if err != nil {
		errStr := fmt.Sprintf("get downlink queue size error: %s", err)
		log.WithField("dev_eui", devEUI).Error(errStr)
		return nil, grpc.Errorf(codes.Internal, errStr)
	}

	if !qi.Confirmed {
		if err := storage.DeleteDownlinkQueueItem(a.ctx.DB, qi.ID); err != nil {
			errStr := fmt.Sprintf("delete downlink queue item error: %s", err)
			log.WithFields(log.Fields{
				"dev_eui": devEUI,
				"id":      qi.ID,
			}).Error(errStr)
			return nil, grpc.Errorf(codes.Internal, errStr)
		}
	} else {
		qi.Pending = true
		if err := storage.UpdateDownlinkQueueItem(a.ctx.DB, *qi); err != nil {
			errStr := fmt.Sprintf("update downlink queue item error: %s", err)
			log.WithFields(log.Fields{
				"dev_eui": devEUI,
				"id":      qi.ID,
			}).Error(errStr)
			return nil, grpc.Errorf(codes.Internal, errStr)
		}
	}

	log.WithFields(log.Fields{
		"dev_eui":   devEUI,
		"confirmed": qi.Confirmed,
		"id":        qi.ID,
		"fcnt":      req.FCnt,
	}).Info("data-down item requested by network-server")

	return &as.GetDataDownResponse{
		Data:      b,
		Confirmed: qi.Confirmed,
		FPort:     uint32(qi.FPort),
		MoreData:  queueSize > 1,
	}, nil

}

// HandleDataDownACK handles an ack on a downlink transmission.
func (a *ApplicationServerAPI) HandleDataDownACK(ctx context.Context, req *as.HandleDataDownACKRequest) (*as.HandleDataDownACKResponse, error) {
	var appEUI, devEUI lorawan.EUI64
	copy(appEUI[:], req.AppEUI)
	copy(devEUI[:], req.DevEUI)

	qi, err := storage.GetPendingDownlinkQueueItem(a.ctx.DB, devEUI)
	if err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}
	if err := storage.DeleteDownlinkQueueItem(a.ctx.DB, qi.ID); err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}
	log.WithFields(log.Fields{
		"dev_eui": qi.DevEUI,
	}).Info("downlink queue item acknowledged")

	err = a.ctx.Handler.SendACKNotification(appEUI, devEUI, handler.ACKNotification{
		DevEUI:    devEUI,
		Reference: qi.Reference,
	})
	if err != nil {
		log.Error("send ack notification to handler error: %s", err)
	}

	return &as.HandleDataDownACKResponse{}, nil
}

// HandleError handles an incoming error.
func (a *ApplicationServerAPI) HandleError(ctx context.Context, req *as.HandleErrorRequest) (*as.HandleErrorResponse, error) {
	var appEUI, devEUI lorawan.EUI64
	copy(appEUI[:], req.AppEUI)
	copy(devEUI[:], req.DevEUI)

	log.WithFields(log.Fields{
		"type":    req.Type,
		"dev_eui": devEUI,
	}).Error(req.Error)

	err := a.ctx.Handler.SendErrorNotification(appEUI, devEUI, handler.ErrorNotification{
		DevEUI: devEUI,
		Type:   req.Type.String(),
		Error:  req.Error,
	})
	if err != nil {
		errStr := fmt.Sprintf("send error notification to mqtt handler error: %s", err)
		log.Error(errStr)
		return nil, grpc.Errorf(codes.Internal, errStr)
	}

	return &as.HandleErrorResponse{}, nil
}

// getAppNonce returns a random application nonce (used for OTAA).
func getAppNonce() ([3]byte, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return b, err
	}
	return b, nil
}

// getNwkSKey returns the network session key.
func getNwkSKey(appkey lorawan.AES128Key, netID lorawan.NetID, appNonce [3]byte, devNonce [2]byte) (lorawan.AES128Key, error) {
	return getSKey(0x01, appkey, netID, appNonce, devNonce)
}

// getAppSKey returns the application session key.
func getAppSKey(appkey lorawan.AES128Key, netID lorawan.NetID, appNonce [3]byte, devNonce [2]byte) (lorawan.AES128Key, error) {
	return getSKey(0x02, appkey, netID, appNonce, devNonce)
}

func getSKey(typ byte, appkey lorawan.AES128Key, netID lorawan.NetID, appNonce [3]byte, devNonce [2]byte) (lorawan.AES128Key, error) {
	var key lorawan.AES128Key
	b := make([]byte, 0, 16)
	b = append(b, typ)

	// little endian
	for i := len(appNonce) - 1; i >= 0; i-- {
		b = append(b, appNonce[i])
	}
	for i := len(netID) - 1; i >= 0; i-- {
		b = append(b, netID[i])
	}
	for i := len(devNonce) - 1; i >= 0; i-- {
		b = append(b, devNonce[i])
	}
	pad := make([]byte, 7)
	b = append(b, pad...)

	block, err := aes.NewCipher(appkey[:])
	if err != nil {
		return key, err
	}
	if block.BlockSize() != len(b) {
		return key, fmt.Errorf("block-size of %d bytes is expected", len(b))
	}
	block.Encrypt(key[:], b)
	return key, nil
}
