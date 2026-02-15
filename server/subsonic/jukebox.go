package subsonic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/core/playback"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/server/subsonic/responses"
	"github.com/navidrome/navidrome/utils/req"
	"github.com/navidrome/navidrome/utils/slice"
)

func (api *Router) JukeboxRemoteFeedback(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := getUser(ctx)
	p := req.Params(r)

	if !conf.Server.Jukebox.Enabled {
		http.Error(rw, "Jukebox is disabled", 404)
		return
	}

	if !conf.Server.Jukebox.RemoteClients {
		http.Error(rw, "Jukebox remote clients are disabled", 404)
	}

	status := playback.DeviceStatus{}
	err := json.NewDecoder(p.Body).Decode(&status)
	log.Debug(ctx, "JukeboxRemoteFeedback received", "playing", status.Playing, "position", status.Position, "index", status.CurrentIndex)
	pb, err := api.playback.GetDeviceForUser(user.UserName)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error retrieving user devices: %s", err), 500)
	}

	err = pb.SetStatus(ctx, status)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error setting status : %s", err), 500)
	}
}

func (api *Router) JukeboxControl(r *http.Request) (*responses.Subsonic, error) {
	ctx := r.Context()
	user := getUser(ctx)
	p := req.Params(r)

	if !conf.Server.Jukebox.Enabled {
		return nil, newError(responses.ErrorGeneric, "Jukebox is disabled")
	}

	if conf.Server.Jukebox.AdminOnly && !user.IsAdmin {
		return nil, newError(responses.ErrorAuthorizationFail, "Jukebox is admin only")
	}

	actionString, err := p.String("action")
	if err != nil {
		return nil, err
	}

	pb, err := api.playback.GetDeviceForUser(user.UserName)
	if err != nil {
		return nil, err
	}
	log.Info(ctx, "JukeboxControl request received", "action", actionString)

	switch actionString {
	case playback.ActionGet:
		mediafiles, status, err := pb.Get(ctx)
		if err != nil {
			return nil, err
		}

		playlist := responses.JukeboxPlaylist{
			JukeboxStatus: *deviceStatusToJukeboxStatus(status),
			Entry:         slice.MapWithArg(mediafiles, ctx, childFromMediaFile),
		}

		response := newResponse()
		response.JukeboxPlaylist = &playlist
		return response, nil
	case playback.ActionStatus:
		return createResponse(pb.Status(ctx))
	case playback.ActionSet:
		ids, _ := p.Strings("id")
		return createResponse(pb.Set(ctx, ids))
	case playback.ActionStart:
		return createResponse(pb.Start(ctx))
	case playback.ActionStop:
		return createResponse(pb.Stop(ctx))
	case playback.ActionSkip:
		index, err := p.Int("index")
		if err != nil {
			return nil, newError(responses.ErrorMissingParameter, "missing parameter index, err: %s", err)
		}
		offset := p.IntOr("offset", 0)
		return createResponse(pb.Skip(ctx, index, offset))
	case playback.ActionAdd:
		ids, _ := p.Strings("id")
		return createResponse(pb.Add(ctx, ids))
	case playback.ActionClear:
		return createResponse(pb.Clear(ctx))
	case playback.ActionRemove:
		index, err := p.Int("index")
		if err != nil {
			return nil, err
		}

		return createResponse(pb.Remove(ctx, index))
	case playback.ActionShuffle:
		return createResponse(pb.Shuffle(ctx))
	case playback.ActionSetGain:
		gainStr, err := p.String("gain")
		if err != nil {
			return nil, newError(responses.ErrorMissingParameter, "missing parameter gain, err: %s", err)
		}

		gain, err := strconv.ParseFloat(gainStr, 32)
		if err != nil {
			return nil, newError(responses.ErrorMissingParameter, "error parsing gain float value, err: %s", err)
		}

		return createResponse(pb.SetGain(ctx, float32(gain)))
	default:
		return nil, newError(responses.ErrorMissingParameter, "Unknown action: %s", actionString)
	}
}

// createResponse is to shorten the case-switch in the JukeboxController
func createResponse(status playback.DeviceStatus, err error) (*responses.Subsonic, error) {
	if err != nil {
		return nil, err
	}
	return statusResponse(status), nil
}

func statusResponse(status playback.DeviceStatus) *responses.Subsonic {
	response := newResponse()
	response.JukeboxStatus = deviceStatusToJukeboxStatus(status)
	return response
}

func deviceStatusToJukeboxStatus(status playback.DeviceStatus) *responses.JukeboxStatus {
	return &responses.JukeboxStatus{
		CurrentIndex: int32(status.CurrentIndex),
		Playing:      status.Playing,
		Gain:         status.Gain,
		Position:     int32(status.Position),
	}
}
