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

type GetCurrentDataRequest struct {
	MeBasePacket
	AttributeMask uint16
}

func (omci *GetCurrentDataRequest) String() string {
	return fmt.Sprintf("%v, Attribute Mask: %#x",
		omci.MeBasePacket.String(), omci.AttributeMask)
}

// LayerType returns LayerTypeGetCurrentDataRequest
func (omci *GetCurrentDataRequest) LayerType() gopacket.LayerType {
	return LayerTypeGetCurrentDataRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetCurrentDataRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeGetCurrentDataRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetCurrentDataRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get Current Data Request into this layer
func (omci *GetCurrentDataRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var offset int
	if omci.Extended {
		offset = 6
	} else {
		offset = 4
	}
	hdrSize := offset + 2
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	// Note: G.988 specifies that an error code of (3) should result if more
	//       than one attribute is requested
	omci.AttributeMask = binary.BigEndian.Uint16(data[offset:])
	return nil
}

func decodeGetCurrentDataRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataRequest{}
	omci.MsgLayerType = LayerTypeGetCurrentDataRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetCurrentDataRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataRequest{}
	omci.MsgLayerType = LayerTypeGetCurrentDataRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Current Data Request message
func (omci *GetCurrentDataRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)
	return nil
}

type GetCurrentDataResponse struct {
	MeBasePacket
	Result                   me.Results
	AttributeMask            uint16
	UnsupportedAttributeMask uint16
	FailedAttributeMask      uint16
	Attributes               me.AttributeValueMap
}

func (omci *GetCurrentDataResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Attribute Mask: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.AttributeMask, omci.Attributes)
}

// LayerType returns LayerTypeGetCurrentDataResponse
func (omci *GetCurrentDataResponse) LayerType() gopacket.LayerType {
	return LayerTypeGetCurrentDataResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetCurrentDataResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeGetCurrentDataResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetCurrentDataResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get Current Data Response into this layer
func (omci *GetCurrentDataResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var offset, length int
	if omci.Extended {
		offset = 6
		length = 7
	} else {
		offset = 4
		length = 3
	}
	hdrSize := offset + length
	err := omci.MeBasePacket.DecodeFromBytes(data, p, hdrSize)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	omci.Result = me.Results(data[offset])
	omci.AttributeMask = binary.BigEndian.Uint16(data[offset+1:])
	switch omci.Result {
	case me.ProcessingError, me.NotSupported, me.UnknownEntity, me.UnknownInstance, me.DeviceBusy:
		return nil // Done (do not try and decode attributes)
	case me.AttributeFailure:
		if omci.Extended {
			omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[offset+3:])
			omci.FailedAttributeMask = binary.BigEndian.Uint16(data[offset+5:])
		} else {
			omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[32:])
			omci.FailedAttributeMask = binary.BigEndian.Uint16(data[34:])
		}
	}
	// Attribute decode. Note that the ITU-T G.988 specification states that the
	//                   Unsupported and Failed attribute masks are always present
	//                   but only valid if the status code== 9.  However some XGS
	//                   ONUs (T&W and Alpha, perhaps more) will use these last 4
	//                   octets for data if the status code == 0 in a baseline GET
	//                   Response. So this behaviour is anticipated here as well
	//                   and will be allowed in favor of greater interoperability.
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[hdrSize:], p, byte(GetCurrentDataResponseType))
	if err != nil {
		return err
	}
	// Validate all attributes support read
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	return errors.New("all Managed Entities have an EntityID attribute")
}

func decodeGetCurrentDataResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataResponse{}
	omci.MsgLayerType = LayerTypeGetCurrentDataResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetCurrentDataResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataResponse{}
	omci.MsgLayerType = LayerTypeGetCurrentDataResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Current Data Message Type Response
func (omci *GetCurrentDataResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support the Get Current Data Message-Type")
	}
	var resultOffset, hdrSize int

	if omci.Extended {
		resultOffset = 2
		hdrSize = resultOffset + 1 + 2 + 2 + 2 // length + result + masks
	} else {
		resultOffset = 0
		hdrSize = resultOffset + 1 + 2 // length + result + attr-mask
	}
	bytes, err := b.AppendBytes(hdrSize)
	if err != nil {
		return err
	}
	bytes[resultOffset] = byte(omci.Result)
	binary.BigEndian.PutUint16(bytes[resultOffset+1:], omci.AttributeMask)

	// Validate all attributes support read
	for attrName := range omci.Attributes {
		var attr *me.AttributeDefinition
		attr, err = me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	// Attribute serialization
	switch omci.Result {
	default:
		if omci.Extended {
			binary.BigEndian.PutUint16(bytes, 7) // Length
			binary.BigEndian.PutUint32(bytes[resultOffset+3:], 0)
		}
		break

	case me.Success, me.AttributeFailure:
		var available int
		if omci.Extended {
			available = MaxExtendedLength - 10 - 3 - 4 - 4 // Less: header, result+mask, optional-masks mic
		} else {
			available = MaxBaselineLength - 8 - 3 - 4 - 8 // hdr, result+mask, optional-masks, trailer
		}
		// Serialize to temporary buffer if we may need to reset values due to
		// recoverable truncation errors
		attributeBuffer := gopacket.NewSerializeBuffer()
		var failedMask uint16
		err, failedMask = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask,
			attributeBuffer, byte(GetCurrentDataResponseType), available, opts.FixLengths)

		if err != nil {
			return err
		}
		if failedMask != 0 {
			// Not all attributes would fit
			omci.FailedAttributeMask |= failedMask
			omci.AttributeMask &= ^failedMask
			omci.Result = me.AttributeFailure

			// Adjust already recorded values
			bytes[resultOffset] = byte(omci.Result)
			binary.BigEndian.PutUint16(bytes[resultOffset+1:], omci.AttributeMask)
		}
		if omci.Extended {
			// Set length and any failure masks
			binary.BigEndian.PutUint16(bytes, uint16(len(attributeBuffer.Bytes())+7))

			if omci.Result == me.AttributeFailure {
				binary.BigEndian.PutUint16(bytes[resultOffset+3:], omci.UnsupportedAttributeMask)
				binary.BigEndian.PutUint16(bytes[resultOffset+5:], omci.FailedAttributeMask)
			} else {
				binary.BigEndian.PutUint32(bytes[resultOffset+3:], 0)
			}
		}
		// Copy over attributes to the original serialization buffer
		var newSpace []byte

		newSpace, err = b.AppendBytes(len(attributeBuffer.Bytes()))
		if err != nil {
			return err
		}
		copy(newSpace, attributeBuffer.Bytes())

		if !omci.Extended {
			// Calculate space left. Max  - msgType header - OMCI trailer - spacedUsedSoFar
			bytesLeft := MaxBaselineLength - 4 - 8 - len(b.Bytes())

			var remainingBytes []byte
			remainingBytes, err = b.AppendBytes(bytesLeft + 4)

			if err != nil {
				return me.NewMessageTruncatedError(err.Error())
			}
			copy(remainingBytes, lotsOfZeros[:])

			if omci.Result == me.AttributeFailure {
				binary.BigEndian.PutUint16(remainingBytes[bytesLeft-4:bytesLeft-2], omci.UnsupportedAttributeMask)
				binary.BigEndian.PutUint16(remainingBytes[bytesLeft-2:bytesLeft], omci.FailedAttributeMask)
			}
		}
	}
	return nil
}
