/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 * Copyright 2020-present Open Networking Foundation

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package meframe

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

func StartSoftwareDownloadRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &StartSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		WindowSize:           opt.software.WindowSize,
		ImageSize:            opt.software.ImageSize,
		NumberOfCircuitPacks: byte(len(opt.software.CircuitPacks)),
		CircuitPacks:         opt.software.CircuitPacks,
	}
	// TODO: Add length check to insure we do not exceed maximum packet size
	// payloadAvailable := int(maxPacketAvailable(m, opt))
	payloadAvailable := 2
	sizeNeeded := 1
	if sizeNeeded > payloadAvailable {
		// TODO: Should we set truncate?
		msg := "out-of-space. Cannot fit Circuit Pack instances into Start Software Download Request message"
		return nil, me.NewMessageTruncatedError(msg)
	}
	return meLayer, nil
}

func StartSoftwareDownloadResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	// Common for all MEs
	meLayer := &StartSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		WindowSize:        opt.software.WindowSize,
		NumberOfInstances: byte(len(opt.software.CircuitPacks)),
		MeResults:         opt.software.Results,
	}
	// TODO: Add length check to insure we do not exceed maximum packet size
	// payloadAvailable := int(maxPacketAvailable(m, opt))
	payloadAvailable := 2
	sizeNeeded := 1
	if sizeNeeded > payloadAvailable {
		// TODO: Should we set truncate?
		msg := "out-of-space. Cannot fit Results  into Start Software Download Response message"
		return nil, me.NewMessageTruncatedError(msg)
	}
	return meLayer, nil
}

func DownloadSectionRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.software.Data == nil {
		return nil, me.NewNonStatusError("Software image data missing")
	}
	// Common for all MEs
	meLayer := &DownloadSectionRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		SectionNumber: opt.software.SectionNumber,
		SectionData:   opt.software.Data,
	}
	return meLayer, nil
}

func DownloadSectionResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	// Common for all MEs
	meLayer := &DownloadSectionResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
		Result:        opt.result,
		SectionNumber: opt.software.SectionNumber,
	}
	return meLayer, nil
}

func EndSoftwareDownloadRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &EndSoftwareDownloadRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func EndSoftwareDownloadResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &EndSoftwareDownloadResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func ActivateSoftwareRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &ActivateSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func ActivateSoftwareResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &ActivateSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func CommitSoftwareRequestFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &CommitSoftwareRequest{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}

func CommitSoftwareResponseFrame(m *me.ManagedEntity, opt options) (gopacket.SerializableLayer, error) {
	if opt.frameFormat == ExtendedIdent {
		return nil, errors.New("extended message set for this message type is not supported")
	}
	mask, err := checkAttributeMask(m, opt.attributeMask)
	if err != nil {
		return nil, err
	}
	// Common for all MEs
	meLayer := &CommitSoftwareResponse{
		MeBasePacket: MeBasePacket{
			EntityClass:    m.GetClassID(),
			EntityInstance: m.GetEntityID(),
			Extended:       opt.frameFormat == ExtendedIdent,
		},
	}
	// Get payload space available
	maxPayload := maxPacketAvailable(m, opt)

	// TODO: Lots of work to do

	fmt.Println(mask, maxPayload)
	return meLayer, errors.New("todo: Not implemented")
}
