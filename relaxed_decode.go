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
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

type UnknownAttributeInfo struct {
	EntityClass    me.ClassID
	EntityInstance uint16
	AttributeMask  uint16
	AttributeData  []byte
}
type UnknownAttributes struct {
	// Each Attributes entry relates one or more unknown attributes to a specific managed
	// entity. For message types such as MIB Upload Next responses, there may be multiple
	// Managed Entities in a single response if the Extended Message set is being used.
	Attributes []UnknownAttributeInfo

	gopacket.Layer
	layers.BaseLayer
	MsgLayerType gopacket.LayerType
}

// SerializeTo provides serialization of an Get Next Message Type Response
func (msg *UnknownAttributes) String() string {
	return fmt.Sprintf("Unknown Attributes, %v Managed Entities", len(msg.Attributes))
}

// LayerType returns LayerTypeGetNextResponse
func (msg *UnknownAttributes) LayerType() gopacket.LayerType {
	return LayerTypeUnknownAttributes
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (msg *UnknownAttributes) CanDecode() gopacket.LayerClass {
	return LayerTypeUnknownAttributes
}

// LayerContents returns the bytes of the packet layer.
func (msg *UnknownAttributes) LayerContents() []byte {
	return msg.Contents
}

// LayerPayload returns the bytes contained within the packet layer
func (msg *UnknownAttributes) LayerPayload() []byte {
	return msg.Payload
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (msg *UnknownAttributes) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// DecodeFromBytes decodes the given bytes of a Get Next Response into this layer
func (msg *UnknownAttributes) DecodeFromBytes(_ []byte, _ gopacket.PacketBuilder) error {
	// This is not a real layer. It is used to pass on relaxed decode error information
	// as an ErrorLayer
	return fmt.Errorf("This function is never called.  This is an error layer that gets assigned")
}

func decodeUnknownAttributes(_ []byte, _ gopacket.PacketBuilder) error {
	return fmt.Errorf("This function is never called.  This is an error layer that gets assigned")
}

func (msg *UnknownAttributes) Error() error {
	return fmt.Errorf("%v managed entities with Unknown Attributes detected during decode",
		len(msg.Attributes))
}

func newUnknownAttributesLayer(prevLayer gopacket.Layer, errInfo []me.IRelaxedDecodeError, p gopacket.PacketBuilder) error {
	// Add the previous layer
	p.AddLayer(prevLayer)

	// Append unknown attributes layer and also set ErrorLayer

	errLayer := &UnknownAttributes{
		Attributes:   make([]UnknownAttributeInfo, 0),
		MsgLayerType: LayerTypeUnknownAttributes,
	}
	for _, item := range errInfo {
		unknown, ok := item.(*me.UnknownAttributeDecodeError)
		if !ok {
			return fmt.Errorf("only UnknownAttributeDecodeError information can be encoded. Found %T",
				unknown)
		}
		data := UnknownAttributeInfo{
			EntityClass:    unknown.EntityClass,
			EntityInstance: unknown.EntityInstance,
			AttributeMask:  unknown.AttributeMask,
		}
		if unknown.Contents != nil {
			data.AttributeData = make([]byte, len(unknown.Contents))
			copy(data.AttributeData, unknown.Contents)
		}
		errLayer.Attributes = append(errLayer.Attributes, data)
	}
	p.AddLayer(errLayer)
	p.SetErrorLayer(errLayer)

	// Return a valid error so that packet decoding stops
	return errLayer.Error()
}
