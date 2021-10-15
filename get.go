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

type GetRequest struct {
	MeBasePacket
	AttributeMask uint16
}

func (omci *GetRequest) String() string {
	return fmt.Sprintf("%v, Mask: %#x",
		omci.MeBasePacket.String(), omci.AttributeMask)
}

// LayerType returns LayerTypeGetRequest
func (omci *GetRequest) LayerType() gopacket.LayerType {
	return LayerTypeGetRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeGetRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get Request into this layer
func (omci *GetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 2
	} else {
		hdrSize = 4 + 2
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
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support Get Message-Type")
	}
	if omci.Extended {
		if len(data) < 8 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		omci.AttributeMask = binary.BigEndian.Uint16(data[6:])
	} else {
		omci.AttributeMask = binary.BigEndian.Uint16(data[4:])
	}
	return nil
}

func decodeGetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetRequest{}
	omci.MsgLayerType = LayerTypeGetRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetRequest{}
	omci.MsgLayerType = LayerTypeGetRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Request message
func (omci *GetRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support Get Message-Type")
	}
	maskOffset := 0
	if omci.Extended {
		maskOffset = 2
	}
	bytes, err := b.AppendBytes(2 + maskOffset)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(2))
	}
	binary.BigEndian.PutUint16(bytes[maskOffset:], omci.AttributeMask)
	return nil
}

type GetResponse struct {
	MeBasePacket
	Result                   me.Results
	AttributeMask            uint16
	Attributes               me.AttributeValueMap
	UnsupportedAttributeMask uint16
	FailedAttributeMask      uint16
}

func (omci *GetResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Mask: %#x, Unsupported: %#x, Failed: %#x, attributes: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.AttributeMask,
		omci.UnsupportedAttributeMask, omci.FailedAttributeMask, omci.Attributes)
}

// LayerType returns LayerTypeGetResponse
func (omci *GetResponse) LayerType() gopacket.LayerType {
	return LayerTypeGetResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeGetResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get Response into this layer
func (omci *GetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+3)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support Get Message-Type")
	}
	if omci.Extended {
		if len(data) < 13 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		omci.Result = me.Results(data[6])
		omci.AttributeMask = binary.BigEndian.Uint16(data[7:])

		// If Attribute failed or Unknown, decode optional attribute mask
		if omci.Result == me.AttributeFailure {
			omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[9:])
			omci.FailedAttributeMask = binary.BigEndian.Uint16(data[11:])
		}
	} else {
		omci.Result = me.Results(data[4])
		omci.AttributeMask = binary.BigEndian.Uint16(data[5:])

		// If Attribute failed or Unknown, decode optional attribute mask
		if omci.Result == me.AttributeFailure {
			omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[32:34])
			omci.FailedAttributeMask = binary.BigEndian.Uint16(data[34:36])
		}
	}
	// Attribute decode. Note that the ITU-T G.988 specification states that the
	//                   Unsupported and Failed attribute masks are always present
	//                   but only valid if the status code== 9.  However some XGS
	//                   ONUs (T&W and Alpha, perhaps more) will use these last 4
	//                   octets for data if the status code == 0.  So accommodate
	//                   this behaviour in favor of greater interoperability.
	firstOctet := 7
	lastOctet := 36
	if omci.Extended {
		firstOctet = 13
		lastOctet = len(data)
	}

	switch omci.Result {
	case me.ProcessingError, me.NotSupported, me.UnknownEntity, me.UnknownInstance, me.DeviceBusy:
		return nil // Done (do not try and decode attributes)

	case me.AttributeFailure:
		if !omci.Extended {
			lastOctet = 32
		}
	}
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask,
		data[firstOctet:lastOctet], p, byte(GetResponseType))
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

func decodeGetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetResponse{}
	omci.MsgLayerType = LayerTypeGetResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetResponse{}
	omci.MsgLayerType = LayerTypeGetResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Response message
func (omci *GetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	if err := omci.MeBasePacket.SerializeTo(b); err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})

	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Get
	if !me.SupportsMsgType(meDefinition, me.Get) {
		return me.NewProcessingError("managed entity does not support the Get Message-Type")
	}
	resultOffset := 0
	attributeErrExtra := 0

	if omci.Extended {
		resultOffset = 2
		attributeErrExtra = 4 // Attribute mask + attribute error masks
	}
	// Space for result + mask (both types) + (len & error masks if extended)
	buffer, err := b.AppendBytes(3 + resultOffset + attributeErrExtra)
	if err != nil {
		return err
	}
	// Save result and initial mask. Other header fields updated after
	// attribute copy
	buffer[resultOffset] = byte(omci.Result)
	binary.BigEndian.PutUint16(buffer[resultOffset+1:], omci.AttributeMask)

	// Validate all attributes requested support read
	for attrName := range omci.Attributes {
		var attr *me.AttributeDefinition
		attr, err = me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && (attr.Mask&omci.AttributeMask != 0) && !me.SupportsAttributeAccess(*attr, me.Read) {
			msg := fmt.Sprintf("attribute '%v' does not support read access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	// Attribute serialization
	switch omci.Result {
	default:
		if omci.Extended {
			// Minimum length is 7 for extended an need to write error masks
			binary.BigEndian.PutUint16(buffer, uint16(7))
			binary.BigEndian.PutUint32(buffer[resultOffset+3:], 0)
		}
		break

	case me.Success, me.AttributeFailure:
		// TODO: Baseline only supported at this time)
		var available int
		if omci.Extended {
			available = MaxExtendedLength - 18 - 4 // Less: header, mic
		} else {
			available = MaxBaselineLength - 11 - 4 - 8 // Less: header, failed attributes, length, mic
		}
		// Serialize to temporary buffer if we may need to reset values due to
		// recoverable truncation errors
		attributeBuffer := gopacket.NewSerializeBuffer()
		var failedMask uint16
		err, failedMask = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask,
			attributeBuffer, byte(GetResponseType), available, opts.FixLengths)

		if err != nil {
			return err
		}
		if failedMask != 0 {
			// Not all attributes would fit
			omci.FailedAttributeMask |= failedMask
			omci.AttributeMask &= ^failedMask
			omci.Result = me.AttributeFailure

			// Adjust already recorded values
			buffer[resultOffset] = byte(omci.Result)
			binary.BigEndian.PutUint16(buffer[resultOffset+1:], omci.AttributeMask)
		}
		if omci.Extended {
			// Set length and any failure masks
			binary.BigEndian.PutUint16(buffer, uint16(len(attributeBuffer.Bytes())+7))

			if omci.Result == me.AttributeFailure {
				binary.BigEndian.PutUint16(buffer[resultOffset+3:], omci.UnsupportedAttributeMask)
				binary.BigEndian.PutUint16(buffer[resultOffset+5:], omci.FailedAttributeMask)
			} else {
				binary.BigEndian.PutUint32(buffer[resultOffset+3:], 0)
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
