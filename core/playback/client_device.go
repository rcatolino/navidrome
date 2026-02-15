package playback

import (
	"context"

	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/server/events"
)

const (
	ActionGet     = "get"
	ActionStatus  = "status"
	ActionSet     = "set"
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionSkip    = "skip"
	ActionAdd     = "add"
	ActionClear   = "clear"
	ActionRemove  = "remove"
	ActionShuffle = "shuffle"
	ActionSetGain = "setGain"
)

type Device interface {
	IsDefault() bool
	Get(ctx context.Context) (model.MediaFiles, DeviceStatus, error)
	GetDeviceName() string
	SetDefault(bool)
	SetUser(string)
	Status(ctx context.Context) (DeviceStatus, error)
	Set(ctx context.Context, ids []string) (DeviceStatus, error)
	Start(ctx context.Context) (DeviceStatus, error)
	Stop(ctx context.Context) (DeviceStatus, error)
	Add(ctx context.Context, ids []string) (DeviceStatus, error)
	Skip(ctx context.Context, index int, offset int) (DeviceStatus, error)
	Clear(ctx context.Context) (DeviceStatus, error)
	Remove(ctx context.Context, index int) (DeviceStatus, error)
	Shuffle(ctx context.Context) (DeviceStatus, error)
	SetGain(ctx context.Context, gain float32) (DeviceStatus, error)
	SetStatus(ctx context.Context, status DeviceStatus) error
}

var _ Device = &playbackDevice{}

// SetStatus implements [Device].
func (p *playbackDevice) SetStatus(ctx context.Context, status DeviceStatus) error {
	panic("unimplemented")
}

func (p *playbackDevice) SetDefault(value bool) {
	p.Default = value
}

func (p *playbackDevice) SetUser(value string) {
	p.User = value
}

func (p *playbackDevice) IsDefault() bool {
	return p.Default
}

// GetDeviceName implements [Device].
func (p *playbackDevice) GetDeviceName() string {
	return p.DeviceName
}

type remoteClientDevice struct {
	serviceCtx           context.Context
	ParentPlaybackServer PlaybackServer
	isDefault            bool
	broker               events.Broker
	status               DeviceStatus
	user                 string
	name                 string
	queue                []model.MediaFile
}

// SetStatus implements [Device].
func (r *remoteClientDevice) SetStatus(ctx context.Context, status DeviceStatus) error {
	r.status = status
	return nil
}

// NewClientDevice creates a new playback device that implements all the basic Jukebox mode commands defined here:
// http://www.subsonic.org/pages/api.jsp#jukeboxControl
// This kind of device only forward jukebox commands to the corresponding client via the event broker.
// Then it's the responsability of the clients to trigger the corresponding actions if supported.
// Starts the trackSwitcher goroutine for the device.
func NewClientDevice(ctx context.Context, playbackServer PlaybackServer, deviceName string) *remoteClientDevice {
	return &remoteClientDevice{
		serviceCtx:           ctx,
		ParentPlaybackServer: playbackServer,
		isDefault:            true,
		broker:               events.GetBroker(),
		status:               DeviceStatus{},
		name:                 deviceName,
	}
}

// Add implements [Device].
func (r *remoteClientDevice) Add(ctx context.Context, ids []string) (DeviceStatus, error) {
	log.Info(ctx, "Jukebox Remote Client, Add request")
	cmd := &events.JukeboxCommand{
		Action: ActionAdd,
		Ids:    ids,
	}
	r.broker.SendBroadcastMessage(ctx, cmd)
	return r.status, nil
}

// Clear implements [Device].
func (r *remoteClientDevice) Clear(ctx context.Context) (DeviceStatus, error) {
	cmd := &events.JukeboxCommand{
		Action: ActionClear,
	}
	r.broker.SendBroadcastMessage(ctx, cmd)
	return r.status, nil
}

// IsDefault implements [Device].
func (r *remoteClientDevice) IsDefault() bool {
	return r.isDefault
}

// GetDeviceName implements [Device].
func (r *remoteClientDevice) GetDeviceName() string {
	return r.name
}

// Get implements [Device].
func (r *remoteClientDevice) Get(ctx context.Context) (model.MediaFiles, DeviceStatus, error) {
	log.Info(ctx, "Jukebox Remote Client, Get request")
	return r.queue, r.status, nil
}

// Remove implements [Device].
func (r *remoteClientDevice) Remove(ctx context.Context, index int) (DeviceStatus, error) {
	log.Info(ctx, "Jukebox Remote Client, Remove request")
	cmd := &events.JukeboxCommand{
		Action: ActionRemove,
		Index:  index,
	}
	r.broker.SendBroadcastMessage(ctx, cmd)
	return r.status, nil
}

// Set implements [Device].
func (r *remoteClientDevice) Set(ctx context.Context, ids []string) (DeviceStatus, error) {
	log.Info(ctx, "Jukebox Remote Client, Set request")
	cmd := &events.JukeboxCommand{
		Action: ActionSet,
		Ids:    ids,
	}
	r.broker.SendBroadcastMessage(ctx, cmd)
	r.status.CurrentIndex = 0
	// Update local queue
	r.queue = []model.MediaFile{}
	for _, id := range ids {
		media, err := r.ParentPlaybackServer.GetMediaFile(id)
		if err != nil {
			log.Warn(ctx, "Error retrieving media file", "id", id, "error", err)
			break
		}

		if media != nil {
			r.queue = append(r.queue, *media)
		}
	}

	if len(ids) > 0 {
		r.status.Playing = true
	} else {
		r.status.Playing = false
	}
	r.status.Position = 0
	return r.status, nil
}

// SetDefault implements [Device].
func (r *remoteClientDevice) SetDefault(bool) {
	r.isDefault = true
}

// SetGain implements [Device].
func (r *remoteClientDevice) SetGain(ctx context.Context, gain float32) (DeviceStatus, error) {
	cmd := &events.JukeboxCommand{
		Action: ActionSetGain,
		Gain:   gain,
	}
	r.status.Gain = gain
	r.broker.SendBroadcastMessage(ctx, cmd)
	return r.status, nil
}

// SetUser implements [Device].
func (r *remoteClientDevice) SetUser(value string) {
	r.user = value
}

// Shuffle implements [Device].
func (r *remoteClientDevice) Shuffle(ctx context.Context) (DeviceStatus, error) {
	cmd := &events.JukeboxCommand{
		Action: ActionSkip,
	}
	r.broker.SendBroadcastMessage(ctx, cmd)
	return r.status, nil
}

// Skip implements [Device].
func (r *remoteClientDevice) Skip(ctx context.Context, index int, offset int) (DeviceStatus, error) {
	cmd := &events.JukeboxCommand{
		Action: ActionSkip,
		Index:  index,
		Offset: offset,
	}
	r.status.CurrentIndex = index
	r.status.Position = offset
	r.broker.SendBroadcastMessage(ctx, cmd)
	return r.status, nil
}

// Start implements [Device].
func (r *remoteClientDevice) Start(ctx context.Context) (DeviceStatus, error) {
	log.Info(ctx, "Jukebox Remote Client, Start request")
	cmd := &events.JukeboxCommand{
		Action: ActionStart,
	}
	r.status.Playing = true
	r.broker.SendBroadcastMessage(ctx, cmd)
	return r.status, nil
}

// Status implements [Device].
func (r *remoteClientDevice) Status(ctx context.Context) (DeviceStatus, error) {
	log.Info(ctx, "Jukebox Remote Client, Status request")
	return r.status, nil
}

// Stop implements [Device].
func (r *remoteClientDevice) Stop(ctx context.Context) (DeviceStatus, error) {
	cmd := &events.JukeboxCommand{
		Action: ActionStop,
	}
	r.broker.SendBroadcastMessage(ctx, cmd)
	r.status.Playing = false
	return r.status, nil
}

var _ Device = &remoteClientDevice{}
