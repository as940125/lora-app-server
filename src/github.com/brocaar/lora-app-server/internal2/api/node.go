package api

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/brocaar/lora-app-server/api"
	"github.com/brocaar/lora-app-server/internal2/api/auth"
	"github.com/brocaar/lora-app-server/internal2/common"
	"github.com/brocaar/lora-app-server/internal2/storage"
	"github.com/brocaar/loraserver/api/ns"
	"github.com/brocaar/lorawan"
)

// NodeAPI exports the Node related functions.
type NodeAPI struct {
	ctx       common.Context
	validator auth.Validator
}

// NewNodeAPI creates a new NodeAPI.
func NewNodeAPI(ctx common.Context, validator auth.Validator) *NodeAPI {
	return &NodeAPI{
		ctx:       ctx,
		validator: validator,
	}
}

// Create creates the given Node.
func (a *NodeAPI) Create(ctx context.Context, req *pb.CreateNodeRequest) (*pb.CreateNodeResponse, error) {
	var appEUI, devEUI lorawan.EUI64
	var appKey lorawan.AES128Key

	if err := appEUI.UnmarshalText([]byte(req.AppEUI)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := devEUI.UnmarshalText([]byte(req.DevEUI)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := appKey.UnmarshalText([]byte(req.AppKey)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}

	if err := a.validator.Validate(ctx,
		auth.ValidateAPIMethod("Node.Create"),
		auth.ValidateApplication(appEUI),
		auth.ValidateNode(devEUI),
	); err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "authentication failed: %s", err)
	}

	node := storage.Node{
		Name:      req.Name,
		DevEUI:    devEUI,
		AppEUI:    appEUI,
		AppKey:    appKey,
		RelaxFCnt: req.RelaxFCnt,

		RXDelay:     uint8(req.RxDelay),
		RX1DROffset: uint8(req.Rx1DROffset),
		RXWindow:    storage.RXWindow(req.RxWindow),
		RX2DR:       uint8(req.Rx2DR),
	}
	if req.ChannelListID > 0 {
		node.ChannelListID = &req.ChannelListID
	}

	if err := storage.CreateNode(a.ctx.DB, node); err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	return &pb.CreateNodeResponse{}, nil
}

// Get returns the Node for the given DevEUI.
func (a *NodeAPI) Get(ctx context.Context, req *pb.GetNodeRequest) (*pb.GetNodeResponse, error) {
	var eui lorawan.EUI64
	if err := eui.UnmarshalText([]byte(req.DevEUI)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}

	node, err := storage.GetNode(a.ctx.DB, eui)
	if err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	if err := a.validator.Validate(ctx,
		auth.ValidateAPIMethod("Node.Get"),
		auth.ValidateApplication(node.AppEUI),
		auth.ValidateNode(node.DevEUI),
	); err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "authentication failed: %s", err)
	}

	devEUI, err := node.DevEUI.MarshalText()
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	appEUI, err := node.AppEUI.MarshalText()
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	appKey, err := node.AppKey.MarshalText()
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}

	resp := pb.GetNodeResponse{
		Name:        node.Name,
		DevEUI:      string(devEUI),
		AppEUI:      string(appEUI),
		AppKey:      string(appKey),
		RxDelay:     uint32(node.RXDelay),
		Rx1DROffset: uint32(node.RX1DROffset),
		RxWindow:    pb.RXWindow(node.RXWindow),
		Rx2DR:       uint32(node.RX2DR),
		RelaxFCnt:   node.RelaxFCnt,
	}

	if node.ChannelListID != nil {
		resp.ChannelListID = *node.ChannelListID
	}

	return &resp, nil
}

// GetList returns a list of nodes (given a limit and offset).
func (a *NodeAPI) List(ctx context.Context, req *pb.ListNodeRequest) (*pb.ListNodeResponse, error) {
	if err := a.validator.Validate(ctx,
		auth.ValidateAPIMethod("Node.List"),
	); err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "authentication failed: %s", err)
	}

	nodes, err := storage.GetNodes(a.ctx.DB, int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	count, err := storage.GetNodesCount(a.ctx.DB)
	return a.returnList(count, nodes)
}

// Update updates the node matching the given DevEUI.
func (a *NodeAPI) Update(ctx context.Context, req *pb.UpdateNodeRequest) (*pb.UpdateNodeResponse, error) {
	var appEUI, devEUI lorawan.EUI64
	var appKey lorawan.AES128Key

	if err := appEUI.UnmarshalText([]byte(req.AppEUI)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := devEUI.UnmarshalText([]byte(req.DevEUI)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := appKey.UnmarshalText([]byte(req.AppKey)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}

	if err := a.validator.Validate(ctx,
		auth.ValidateAPIMethod("Node.Update"),
		auth.ValidateApplication(appEUI),
		auth.ValidateNode(devEUI),
	); err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "authentication failed: %s", err)
	}

	node, err := storage.GetNode(a.ctx.DB, devEUI)
	if err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	node.Name = req.Name
	node.AppEUI = appEUI
	node.AppKey = appKey
	node.RXDelay = uint8(req.RxDelay)
	node.RX1DROffset = uint8(req.Rx1DROffset)
	node.RXWindow = storage.RXWindow(req.RxWindow)
	node.RX2DR = uint8(req.Rx2DR)
	node.RelaxFCnt = req.RelaxFCnt
	if req.ChannelListID > 0 {
		node.ChannelListID = &req.ChannelListID
	} else {
		node.ChannelListID = nil
	}

	if err := storage.UpdateNode(a.ctx.DB, node); err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	return &pb.UpdateNodeResponse{}, nil
}

// Delete deletes the node matching the given DevEUI.
func (a *NodeAPI) Delete(ctx context.Context, req *pb.DeleteNodeRequest) (*pb.DeleteNodeResponse, error) {
	var eui lorawan.EUI64
	if err := eui.UnmarshalText([]byte(req.DevEUI)); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, err.Error())
	}

	// get the node so we can validate if the user has access to this
	// application
	node, err := storage.GetNode(a.ctx.DB, eui)
	if err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	if err := a.validator.Validate(ctx,
		auth.ValidateAPIMethod("Node.Delete"),
		auth.ValidateApplication(node.AppEUI),
		auth.ValidateNode(node.DevEUI),
	); err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "authentication failed: %s", err)
	}

	if err := storage.DeleteNode(a.ctx.DB, eui); err != nil {
		return nil, grpc.Errorf(codes.Unknown, err.Error())
	}

	// try to delete the node-session
	_, _ = a.ctx.NetworkServer.DeleteNodeSession(context.Background(), &ns.DeleteNodeSessionRequest{
		DevEUI: eui[:],
	})

	return &pb.DeleteNodeResponse{}, nil
}

func (a *NodeAPI) returnList(count int, nodes []storage.Node) (*pb.ListNodeResponse, error) {
	resp := pb.ListNodeResponse{
		TotalCount: int64(count),
	}
	for _, node := range nodes {
		appEUI, err := node.AppEUI.MarshalText()
		if err != nil {
			return nil, grpc.Errorf(codes.Internal, err.Error())
		}
		devEUI, err := node.DevEUI.MarshalText()
		if err != nil {
			return nil, grpc.Errorf(codes.Internal, err.Error())
		}
		appKey, err := node.AppKey.MarshalText()
		if err != nil {
			return nil, grpc.Errorf(codes.Internal, err.Error())
		}

		item := pb.GetNodeResponse{
			Name:        node.Name,
			DevEUI:      string(devEUI),
			AppEUI:      string(appEUI),
			AppKey:      string(appKey),
			RxDelay:     uint32(node.RXDelay),
			Rx1DROffset: uint32(node.RX1DROffset),
			RxWindow:    pb.RXWindow(node.RXWindow),
			Rx2DR:       uint32(node.RX2DR),
			RelaxFCnt:   node.RelaxFCnt,
		}

		if node.ChannelListID != nil {
			item.ChannelListID = *node.ChannelListID
		}

		resp.Result = append(resp.Result, &item)
	}
	return &resp, nil
}
