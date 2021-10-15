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

type AttributeValueChangeMsg struct {
	MeBasePacket
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *AttributeValueChangeMsg) String() string {
	return fmt.Sprintf("%v, Mask: %#x, attributes: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.Attributes)
}

// LayerType returns LayerTypeAttributeValueChange
func (omci *AttributeValueChangeMsg) LayerType() gopacket.LayerType {
	return LayerTypeAttributeValueChange
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *AttributeValueChangeMsg) CanDecode() gopacket.LayerClass {
	return LayerTypeAttributeValueChange
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *AttributeValueChangeMsg) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of an Attribute Value Change notification into this layer
func (omci *AttributeValueChangeMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+2)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// TODO: Support for encoding AVC into message type support not yet supported
	//if !me.SupportsMsgType(meDefinition, me.AlarmNotification) {
	//	return me.NewProcessingError("managed entity does not support Alarm Notification Message-Type")
	//}
	maskOffset := 4
	if omci.Extended {
		maskOffset = 6
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[maskOffset:])
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[maskOffset+2:],
		p, byte(AttributeValueChangeType))
	// TODO: Add support for attributes that can have an AVC associated with them and then add a check here
	// Validate all attributes support AVC
	//for attrName := range omci.attributes {
	//	attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
	//	if err != nil {
	//		return err
	//	}
	//	if attr.Index != 0 && !me.SupportsAttributeAVC(attr) {
	//		msg := fmt.Sprintf("attribute '%v' does not support AVC notifications", attrName)
	//		return me.NewProcessingError(msg)
	//	}
	//}
	return err
}

func decodeAttributeValueChange(data []byte, p gopacket.PacketBuilder) error {
	omci := &AttributeValueChangeMsg{}
	omci.MsgLayerType = LayerTypeAttributeValueChange
	return decodingLayerDecoder(omci, data, p)
}

func decodeAttributeValueChangeExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &AttributeValueChangeMsg{}
	omci.MsgLayerType = LayerTypeAttributeValueChange
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Attribute Value Change Notification message
func (omci *AttributeValueChangeMsg) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// TODO: Add support for attributes that can have an AVC associated with them and then add a check here
	// Validate all attributes support AVC
	//for attrName := range omci.attributes {
	//	attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
	//	if err != nil {
	//		return err
	//	}
	//	if attr.Index != 0 && !me.SupportsAttributeAVC(attr) {
	//		msg := fmt.Sprintf("attribute '%v' does not support AVC notifications", attrName)
	//		return me.NewProcessingError(msg)
	//	}
	//}
	var maskOffset int
	var bytesAvailable int
	if omci.Extended {
		maskOffset = 2
		bytesAvailable = MaxExtendedLength - 12 - 4
	} else {
		maskOffset = 0
		bytesAvailable = MaxBaselineLength - 10 - 8
	}
	bytes, err := b.AppendBytes(maskOffset + 2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[maskOffset:], omci.AttributeMask)

	// Attribute serialization
	attributeBuffer := gopacket.NewSerializeBuffer()
	if err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask,
		attributeBuffer, byte(GetResponseType), bytesAvailable, false); err != nil {
		return err
	}

	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(len(attributeBuffer.Bytes())+2))
	}
	bytes, err = b.AppendBytes(len(attributeBuffer.Bytes()))
	if err != nil {
		return err
	}
	copy(bytes, attributeBuffer.Bytes())
	return nil
}
