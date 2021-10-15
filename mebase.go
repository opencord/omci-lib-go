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
	"github.com/google/gopacket/layers"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

type MeBasePacket struct {
	EntityClass    me.ClassID
	EntityInstance uint16

	gopacket.Layer
	layers.BaseLayer
	MsgLayerType gopacket.LayerType
	Extended     bool
}

func (msg *MeBasePacket) String() string {
	return fmt.Sprintf("ClassID: %v, InstanceId: %d/%#x",
		msg.EntityClass, msg.EntityInstance, msg.EntityInstance)
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (msg *MeBasePacket) CanDecode() gopacket.LayerClass {
	return msg.MsgLayerType
}

// LayerType returns MsgLayerType. It partially satisfies Layer and SerializableLayer
func (msg *MeBasePacket) LayerType() gopacket.LayerType {
	return msg.MsgLayerType
}

// LayerContents returns the bytes of the packet layer.
func (msg *MeBasePacket) LayerContents() []byte {
	return msg.Contents
}

// LayerPayload returns the bytes contained within the packet layer
func (msg *MeBasePacket) LayerPayload() []byte {
	return msg.Payload
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (msg *MeBasePacket) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// DecodeFromBytes decodes the given bytes into this layer
func (msg *MeBasePacket) DecodeFromBytes(data []byte, p gopacket.PacketBuilder, contentSize int) error {
	if len(data) < contentSize {
		p.SetTruncated()
		layerType := msg.LayerType().String()
		if msg.Extended {
			layerType += " (extended)"
		}
		return fmt.Errorf("frame header too small. %v header length %v, %v required",
			layerType, len(data), contentSize)
	}
	msg.EntityClass = me.ClassID(binary.BigEndian.Uint16(data[0:]))
	msg.EntityInstance = binary.BigEndian.Uint16(data[2:])
	msg.BaseLayer = layers.BaseLayer{Contents: data[:contentSize], Payload: data[contentSize:]}
	return nil
}

// SerializeTo provides serialization of this message layer
func (msg *MeBasePacket) SerializeTo(b gopacket.SerializeBuffer) error {
	// Add class ID and entity ID
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, uint16(msg.EntityClass))
	binary.BigEndian.PutUint16(bytes[2:], msg.EntityInstance)
	return nil
}

type layerDecodingLayer interface {
	gopacket.Layer
	DecodeFromBytes([]byte, gopacket.PacketBuilder) error
	NextLayerType() gopacket.LayerType
}

func decodingLayerDecoder(d layerDecodingLayer, data []byte, p gopacket.PacketBuilder) error {
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)
	next := d.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}
