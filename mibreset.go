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

type MibResetRequest struct {
	MeBasePacket
}

func (omci *MibResetRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// LayerType returns LayerTypeMibResetRequest
func (omci *MibResetRequest) LayerType() gopacket.LayerType {
	return LayerTypeMibResetRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *MibResetRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeMibResetRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *MibResetRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a MIB Reset Request into this layer
func (omci *MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6
	} else {
		hdrSize = 4
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
	// ME needs to support MIB reset
	if !me.SupportsMsgType(meDefinition, me.MibReset) {
		return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for MIB Reset request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Reset request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	return nil
}

func decodeMibResetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetRequest{}
	omci.MsgLayerType = LayerTypeMibResetRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeMibResetRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetRequest{}
	omci.MsgLayerType = LayerTypeMibResetRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Reset Request message
func (omci *MibResetRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// MibReset Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		return me.NewProcessingError("invalid Entity Class for MIB Reset request")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for MIB Reset request")
	}
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	// Add length if extended ident
	if omci.Extended {
		bytes, err := b.AppendBytes(2)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, 0)
	}
	return nil
}

type MibResetResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *MibResetResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// LayerType returns LayerTypeMibResetResponse
func (omci *MibResetResponse) LayerType() gopacket.LayerType {
	return LayerTypeMibResetResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *MibResetResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeMibResetResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *MibResetResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a MIB Reset Response into this layer
func (omci *MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 1
	} else {
		hdrSize = 4 + 1
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
	// ME needs to support MIB reset
	if !me.SupportsMsgType(meDefinition, me.MibReset) {
		return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		return me.NewProcessingError("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for MIB Reset Response")
	}
	offset := hdrSize - 1
	omci.Result = me.Results(data[offset])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeMibResetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetResponse{}
	omci.MsgLayerType = LayerTypeMibResetResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeMibResetResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetResponse{}
	omci.MsgLayerType = LayerTypeMibResetResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Reset Response message
func (omci *MibResetResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Set
	if !me.SupportsMsgType(entity, me.MibReset) {
		return me.NewProcessingError("managed entity does not support the MIB Reset Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 1)
	if err != nil {
		return err
	}
	// Add length if extended ident
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 1)
	}
	bytes[offset] = byte(omci.Result)
	return nil
}
