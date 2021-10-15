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
	"math/bits"
)

type SetTableRequest struct {
	MeBasePacket
	AttributeMask uint16
	// Attributes below should be a single attribute whose value is of type TableRows
	Attributes me.AttributeValueMap
}

func (omci *SetTableRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// LayerType returns LayerTypeSetTableRequest
func (omci *SetTableRequest) LayerType() gopacket.LayerType {
	return LayerTypeSetTableRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *SetTableRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeSetTableRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *SetTableRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Set Table Request into this layer
func (omci *SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Only supported in the Extended message set
	if !omci.Extended {
		return me.NewNotSupportedError("baseline message set not supported by SetTable Message-Type")
	}
	// Common ClassID/EntityID decode in msgBase
	hdrSize := 6 + 2

	if len(data) < hdrSize {
		p.SetTruncated()
		return errors.New("frame too small")
	} // Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 6+2)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support SetTable
	if !me.SupportsMsgType(meDefinition, me.SetTable) {
		return me.NewProcessingError("managed entity does not support SetTable Message-Type")
	}
	offset := hdrSize - 2
	omci.AttributeMask = binary.BigEndian.Uint16(data[offset:])

	// Only a single attribute bit can be set
	if bits.OnesCount16(omci.AttributeMask) != 1 {
		return me.NewProcessingError("only a single attribute can be specified for the SetTable Message-Type")
	}
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[hdrSize:], p, byte(SetTableRequestType))
	if err != nil {
		return err
	}
	// Validate that the selected attribute support write and is a table
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && attr.Mask == omci.AttributeMask {
			if !me.SupportsAttributeAccess(*attr, me.Write) {
				msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
				return me.NewProcessingError(msg)
			}
			if !attr.IsTableAttribute() {
				msg := fmt.Sprintf("attribute '%v' must be a table attribute for a SetTable Message-Type", attrName)
				return me.NewProcessingError(msg)
			}
			break
		}
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	return me.NewProcessingError("All Managed Entities have an EntityID attribute")
}

func decodeSetTableRequest(data []byte, p gopacket.PacketBuilder) error {
	return me.NewNotSupportedError("baseline message set not supported by SetTable Message-Type")
}

func decodeSetTableRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableRequest{}
	omci.MsgLayerType = LayerTypeSetTableRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Table Message Type Request
func (omci *SetTableRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Only Extended message set is supported for this message type
	if !omci.Extended {
		return me.NewNotSupportedError("only Extended Message set support for the SetTable Message-Type")
	}
	// Basic (common) OMCI Header
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support SetTable
	if !me.SupportsMsgType(meDefinition, me.SetTable) {
		return me.NewProcessingError("managed entity does not support SetTable Message-Type")
	}
	// Only a single attribute bit can be set for this request
	if bits.OnesCount16(omci.AttributeMask) != 1 {
		return me.NewProcessingError("only a single attribute can be specified for the SetTable Message-Type")
	}
	// Find the attributes and make sure it supports a write
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		// Do not test for write of Entity ID in the attribute list
		if attr.Index != 0 && attr.Mask == omci.AttributeMask {
			// Must be a table attribute and support writes
			if !me.SupportsAttributeAccess(*attr, me.Write) {
				msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
				return me.NewProcessingError(msg)
			}
			if !attr.IsTableAttribute() {
				msg := fmt.Sprintf("attribute '%v' must be a table attribute for a SetTable Message-Type", attrName)
				return me.NewProcessingError(msg)
			}
			break
		}
	}
	// Attribute serialization
	maskOffset := 1
	maskOffset = 2
	bytesAvailable := MaxExtendedLength - 12 - 4
	attributeBuffer := gopacket.NewSerializeBuffer()
	if attrErr, _ := meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, attributeBuffer,
		byte(SetTableRequestType), bytesAvailable, false); attrErr != nil {
		return attrErr
	}
	bytes, err := b.AppendBytes(maskOffset + 2 + len(attributeBuffer.Bytes()))
	if err != nil {
		return err
	}
	// Encode the length nd attribute mask
	binary.BigEndian.PutUint16(bytes, uint16(len(attributeBuffer.Bytes())+2))
	binary.BigEndian.PutUint16(bytes[maskOffset:], omci.AttributeMask)
	copy(bytes[maskOffset+2:], attributeBuffer.Bytes())
	return nil
}

type SetTableResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *SetTableResponse) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// LayerType returns LayerTypeSetTableResponse
func (omci *SetTableResponse) LayerType() gopacket.LayerType {
	return LayerTypeSetTableResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *SetTableResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeSetTableResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *SetTableResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Set Table Response into this layer
func (omci *SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 6+1)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support SetTable
	if !me.SupportsMsgType(entity, me.SetTable) {
		return me.NewProcessingError("managed entity does not support the SetTable Message-Type")
	}
	omci.Result = me.Results(data[6])
	if omci.Result == 7 || omci.Result == 8 || omci.Result >= 9 {
		msg := fmt.Sprintf("invalid SetTable results code: %v, must be 0..6, 9", omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeSetTableResponse(data []byte, p gopacket.PacketBuilder) error {
	return me.NewNotSupportedError("baseline message set not supported by SetTable Message-Type")
}

func decodeSetTableResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableResponse{}
	omci.MsgLayerType = LayerTypeSetTableResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Table Message Type Response
func (omci *SetTableResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support SetTable
	if !me.SupportsMsgType(entity, me.SetTable) {
		return me.NewProcessingError("managed entity does not support the SetTable Message-Type")
	}
	offset := 2
	length := 1
	bytes, err := b.AppendBytes(offset + length)
	if err != nil {
		return err
	}
	if omci.Result == 7 || omci.Result == 8 || omci.Result >= 9 {
		msg := fmt.Sprintf("invalid SetTable results code: %v, must be 0..6, 9", omci.Result)
		return errors.New(msg)
	}
	// TODO: Section A.1.1 (page 505) of ITU-G.988-202003 specifies that:
	//   When the result-reason code in a response message indicates an exception (i.e., its
	//   value is not 0), the response message is permitted to include vendor-specific
	//   additional information. The rules for additional error information are as follows.
	//
	//     1.	Additional error information is optional for the ONU to insert.
	//     2.	Additional information may or may not be represented in textual form.
	//     3.	The semantics of additional error information are specific to the ONU vendor.
	//     4.	The ONU must not rely on the OLT being able to detect or interpret additional
	//    		error information.
	//     5.	Additional error information may occupy only padding bytes (baseline message set)
	//    		or only uncommitted trailing bytes (extended message set).
	//     6.	In get, get current data and get next responses, the attribute mask controls the
	//    		padding definition.
	//     7.	No additional error information is permitted in responses to start download and
	//    		end download messages that are directed to multiple target MEs, as indicated by
	//   		0xFFFF in the target ME identifier.
	//
	// TODO: Add this capability to all appropriate response serializations and validate for
	//       decodes the information is available through the Payload() function of the message-type

	binary.BigEndian.PutUint16(bytes, uint16(1))
	bytes[offset] = byte(omci.Result)
	return nil
}
