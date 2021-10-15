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

package omci

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

type SynchronizeTimeRequest struct {
	MeBasePacket
	Year   uint16
	Month  uint8
	Day    uint8
	Hour   uint8
	Minute uint8
	Second uint8
}

func (omci *SynchronizeTimeRequest) String() string {
	return fmt.Sprintf("%v, Date-Time: %d/%d/%d-%02d:%02d:%02d",
		omci.MeBasePacket.String(), omci.Year, omci.Month, omci.Day, omci.Hour, omci.Minute, omci.Second)
}

// LayerType returns LayerTypeSynchronizeTimeRequest
func (omci *SynchronizeTimeRequest) LayerType() gopacket.LayerType {
	return LayerTypeSynchronizeTimeRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *SynchronizeTimeRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeSynchronizeTimeRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *SynchronizeTimeRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Synchronize Time Request into this layer
func (omci *SynchronizeTimeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	getDateAndTime := true
	var offset, hdrSize int
	if omci.Extended {
		offset = 6
		hdrSize = offset + 7
		// Extended format allows for the OLT to support not setting the date and
		// time (not present in the message)
		// TODO: There is not a way to indicate this to the user at this time, currently
		//       all date/time fields will be zero
		if len(data) < offset {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		if len(data) < hdrSize {
			getDateAndTime = false
			hdrSize = len(data)
		}
	} else {
		offset = 4
		hdrSize := offset + 7
		if len(data) < hdrSize {
			p.SetTruncated()
			return errors.New("frame too small")
		}
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(meDefinition, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support Synchronize Time Message-Type")
	}
	// Synchronize Time Entity Class are always ONU-G (256) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassID {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time request")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time request")
	}

	if getDateAndTime {
		omci.Year = binary.BigEndian.Uint16(data[offset:])
		omci.Month = data[offset+2]
		omci.Day = data[offset+3]
		omci.Hour = data[offset+4]
		omci.Minute = data[offset+5]
		omci.Second = data[offset+6]
	}
	return nil
}

func decodeSynchronizeTimeRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeRequest{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeSynchronizeTimeRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeRequest{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Synchronize Time Request message
func (omci *SynchronizeTimeRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(entity, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	var offset, length int
	if omci.Extended {
		// TODO: Extended format allows for the OLT to support not setting the date and
		//       time (not present in the message). This needs to be supported in a future
		//       version of the software.
		offset = 2
		length = 7
	} else {
		offset = 0
		length = 7
	}
	bytes, err := b.AppendBytes(offset + length)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(length))
	}
	binary.BigEndian.PutUint16(bytes[offset:], omci.Year)
	if length > 0 {
		bytes[offset+2] = omci.Month
		bytes[offset+3] = omci.Day
		bytes[offset+4] = omci.Hour
		bytes[offset+5] = omci.Minute
		bytes[offset+6] = omci.Second
	}
	return nil
}

type SynchronizeTimeResponse struct {
	MeBasePacket
	Result         me.Results
	SuccessResults uint8 // Only if 'Result' is 0 -> success
}

func (omci *SynchronizeTimeResponse) String() string {
	return fmt.Sprintf("%v, Results: %d (%v), Success: %d",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.SuccessResults)
}

// LayerType returns LayerTypeSynchronizeTimeResponse
func (omci *SynchronizeTimeResponse) LayerType() gopacket.LayerType {
	return LayerTypeSynchronizeTimeResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *SynchronizeTimeResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeSynchronizeTimeResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *SynchronizeTimeResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Synchronize Time Response into this layer
func (omci *SynchronizeTimeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize, offset int
	if omci.Extended {
		offset = 6
		hdrSize = offset + 1
		// TODO: Extended message set allows for the optional encoding of the of the
		//       12th octet (success results) even if the result code is not 0/success.
		//       This functionality is not currently supported.
	} else {
		offset = 4
		hdrSize = offset + 2
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(meDefinition, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support Synchronize Time Message-Type")
	}
	// Synchronize Time Entity Class are always ONU-G (256) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassID {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time response")
	}

	omci.Result = me.Results(data[offset])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	if omci.Result == me.Success && len(data) > offset+1 {
		omci.SuccessResults = data[offset+1]
	} else if omci.Extended && len(data) > offset+1 {
		omci.SuccessResults = data[offset+1]
	}
	return nil
}

func decodeSynchronizeTimeResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeResponse{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeSynchronizeTimeResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeResponse{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Synchronize Time Response message
func (omci *SynchronizeTimeResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// Synchronize Time Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassID {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time response")
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(entity, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	} else {
		offset = 0
	}
	numBytes := 2
	if omci.Result != me.Success {
		// TODO: Extended message set allows for the optional encoding of the of the
		//       12th octet (success results) even if the result code is not 0/success.
		//       This functionality is not currently supported
		numBytes = 1
	}
	bytes, err := b.AppendBytes(offset + numBytes)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(numBytes))
	}
	bytes[offset] = uint8(omci.Result)
	if omci.Result == me.Success {
		// TODO: Extended message set allows for the optional encoding of the of the
		//       12th octet (success results) even if the result code is not 0/success.
		//       This functionality is not currently supported
		bytes[offset+1] = omci.SuccessResults
	}
	return nil
}
