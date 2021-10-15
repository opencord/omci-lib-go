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
	"fmt"
	"github.com/google/gopacket"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

type DeleteRequest struct {
	MeBasePacket
}

func (omci *DeleteRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// LayerType returns LayerTypeDeleteRequest
func (omci *DeleteRequest) LayerType() gopacket.LayerType {
	return LayerTypeDeleteRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *DeleteRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeDeleteRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *DeleteRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Delete Request into this layer
func (omci *DeleteRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	return nil
}

func decodeDeleteRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteRequest{}
	omci.MsgLayerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeDeleteRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteRequest{}
	omci.MsgLayerType = LayerTypeDeleteRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Delete Request message
func (omci *DeleteRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	if omci.Extended {
		bytes, err := b.AppendBytes(2)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, 0)
	}
	return nil
}

type DeleteResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *DeleteResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// LayerType returns LayerTypeDeleteResponse
func (omci *DeleteResponse) LayerType() gopacket.LayerType {
	return LayerTypeDeleteResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *DeleteResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeDeleteResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *DeleteResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Delete Response into this layer
func (omci *DeleteResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	offset := hdrSize - 1
	omci.Result = me.Results(data[offset])
	return nil
}

func decodeDeleteResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteResponse{}
	omci.MsgLayerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeDeleteResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteResponse{}
	omci.MsgLayerType = LayerTypeDeleteResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Delete Response message
func (omci *DeleteResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Delete
	if !me.SupportsMsgType(entity, me.Delete) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	} else {
		offset = 0
	}
	bytes, err := b.AppendBytes(offset + 1)
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 1)
	}
	if err != nil {
		return err
	}
	bytes[offset] = byte(omci.Result)
	return nil
}
