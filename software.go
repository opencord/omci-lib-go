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

type StartSoftwareDownloadRequest struct {
	MeBasePacket                // Note: EntityInstance for software download is two specific values
	WindowSize           byte   // Window Size -1
	ImageSize            uint32 // Octets
	NumberOfCircuitPacks byte
	CircuitPacks         []uint16 // MSB & LSB of software image instance
}

func (omci *StartSoftwareDownloadRequest) String() string {
	return fmt.Sprintf("%v, Window Size: %v, Image Size: %v, # Circuit Packs: %v",
		omci.MeBasePacket.String(), omci.WindowSize, omci.ImageSize, omci.NumberOfCircuitPacks)
}

// LayerType returns LayerTypeStartSoftwareDownloadRequest
func (omci *StartSoftwareDownloadRequest) LayerType() gopacket.LayerType {
	return LayerTypeStartSoftwareDownloadRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *StartSoftwareDownloadRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeStartSoftwareDownloadRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *StartSoftwareDownloadRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Start Software Download Request into this layer
func (omci *StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 4
	} else {
		hdrSize = 4 + 4
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
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download request")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.WindowSize = data[offset+4]
	omci.ImageSize = binary.BigEndian.Uint32(data[offset+5:])
	omci.NumberOfCircuitPacks = data[offset+9]
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks))
	}
	omci.CircuitPacks = make([]uint16, omci.NumberOfCircuitPacks)
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		omci.CircuitPacks[index] = binary.BigEndian.Uint16(data[offset+10+(index*2):])
	}
	return nil
}

func decodeStartSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeStartSoftwareDownloadRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Start Software Download Request message
func (omci *StartSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(entity, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support the Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download request")
	}
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks))
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 6 + (2 * int(omci.NumberOfCircuitPacks)))
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(6+(2*int(omci.NumberOfCircuitPacks))))
	}
	bytes[offset] = omci.WindowSize
	binary.BigEndian.PutUint32(bytes[offset+1:], omci.ImageSize)
	bytes[offset+5] = omci.NumberOfCircuitPacks
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		binary.BigEndian.PutUint16(bytes[offset+6+(index*2):], omci.CircuitPacks[index])
	}
	return nil
}

type DownloadResults struct {
	ManagedEntityID uint16 // ME ID of software image entity instance (slot number plus instance 0..1 or 2..254 vendor-specific)
	Result          me.Results
}

func (dr *DownloadResults) String() string {
	return fmt.Sprintf("ME: %v (%#x), Results: %d (%v)", dr.ManagedEntityID, dr.ManagedEntityID,
		dr.Result, dr.Result)
}

type StartSoftwareDownloadResponse struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	Result            me.Results
	WindowSize        byte // Window Size -1
	NumberOfInstances byte
	MeResults         []DownloadResults
}

func (omci *StartSoftwareDownloadResponse) String() string {
	return fmt.Sprintf("%v, Results: %v, Window Size: %v, # of Instances: %v, ME Results: %v",
		omci.MeBasePacket.String(), omci.Result, omci.WindowSize, omci.NumberOfInstances, omci.MeResults)
}

// LayerType returns LayerTypeStartSoftwareDownloadResponse
func (omci *StartSoftwareDownloadResponse) LayerType() gopacket.LayerType {
	return LayerTypeStartSoftwareDownloadResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *StartSoftwareDownloadResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeStartSoftwareDownloadResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *StartSoftwareDownloadResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Start Software Download Response into this layer
func (omci *StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 3
	} else {
		hdrSize = 4 + 3
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
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download response")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.Result = me.Results(data[offset+4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.WindowSize = data[offset+5]
	omci.NumberOfInstances = data[offset+6]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		// TODO: Calculate additional space needed and see if it is truncated
		omci.MeResults = make([]DownloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[offset+7+(index*3):])
			omci.MeResults[index].Result = me.Results(data[offset+9+(index*3)])
			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for Start Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
		}
	}
	return nil
}

func decodeStartSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeStartSoftwareDownloadResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Start Software Download Response message
func (omci *StartSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download response")
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 3 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(3+(3*int(omci.NumberOfInstances))))
	}
	bytes[offset] = byte(omci.Result)
	bytes[offset+1] = omci.WindowSize
	bytes[offset+2] = omci.NumberOfInstances

	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[offset+3+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for Start Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[offset+5+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

// DownloadSectionRequest data is bound by the message set in use. For the
// Baseline message set use MaxDownloadSectionLength and for the Extended message
// set, MaxDownloadSectionExtendedLength is provided
type DownloadSectionRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	SectionNumber byte
	SectionData   []byte // 0 padding if final transfer requires only a partial block for baseline set
}

func (omci *DownloadSectionRequest) String() string {
	return fmt.Sprintf("%v, Section #: %v, Data Length: %v",
		omci.MeBasePacket.String(), omci.SectionNumber, len(omci.SectionData))
}

// LayerType returns LayerTypeDownloadSectionRequest
func (omci *DownloadSectionRequest) LayerType() gopacket.LayerType {
	return LayerTypeDownloadSectionRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *DownloadSectionRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeDownloadSectionRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *DownloadSectionRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Download Section Request into this layer
func (omci *DownloadSectionRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+1)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section request")
	}
	if omci.Extended {
		if len(data) < 7 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		if len(data[7:]) > MaxDownloadSectionExtendedLength {
			return errors.New(fmt.Sprintf("software image data too large. Received %v, Max: %v",
				len(data[7:]), MaxDownloadSectionExtendedLength))
		}
		omci.SectionData = make([]byte, len(data[7:]))
		omci.SectionNumber = data[6]
		copy(omci.SectionData, data[7:])
	} else {
		if len(data[5:]) != MaxDownloadSectionLength {
			p.SetTruncated()
			return errors.New(fmt.Sprintf("software image size invalid. Received %v, Expected: %v",
				len(data[5:]), MaxDownloadSectionLength))
		}
		omci.SectionData = make([]byte, MaxDownloadSectionLength)
		omci.SectionNumber = data[4]
		copy(omci.SectionData, data[5:])
	}
	return nil
}

func decodeDownloadSectionRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.MsgLayerType = LayerTypeDownloadSectionRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeDownloadSectionRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.MsgLayerType = LayerTypeDownloadSectionRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Download Section Request message
func (omci *DownloadSectionRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	sectionLength := len(omci.SectionData)
	if omci.Extended {
		if sectionLength > MaxDownloadSectionExtendedLength {
			msg := fmt.Sprintf("invalid Download Section data length, must be <= %v, received: %v",
				MaxDownloadSectionExtendedLength, sectionLength)
			return me.NewProcessingError(msg)
		}
		// Append section data
		bytes, err := b.AppendBytes(3 + sectionLength)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16(1+sectionLength))
		bytes[2] = omci.SectionNumber
		copy(bytes[3:], omci.SectionData)
	} else {
		if sectionLength > MaxDownloadSectionLength {
			msg := fmt.Sprintf("invalid Download Section data length, must be <= %v, received: %v",
				MaxDownloadSectionLength, sectionLength)
			return me.NewProcessingError(msg)
		}
		// Append section data
		bytes, err := b.AppendBytes(1 + MaxDownloadSectionLength)
		if err != nil {
			return err
		}
		bytes[0] = omci.SectionNumber
		copy(bytes[1:], omci.SectionData)

		// Zero extended if needed
		if sectionLength < MaxDownloadSectionLength {
			copy(omci.SectionData[sectionLength:], lotsOfZeros[:MaxDownloadSectionLength-sectionLength])
		}
	}
	return nil
}

type DownloadSectionResponse struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	Result        me.Results
	SectionNumber byte
}

func (omci *DownloadSectionResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Section #: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.SectionNumber)
}

// LayerType returns LayerTypeDownloadSectionResponse
func (omci *DownloadSectionResponse) LayerType() gopacket.LayerType {
	return LayerTypeDownloadSectionResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *DownloadSectionResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeDownloadSectionResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *DownloadSectionResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Download Section Response into this layer
func (omci *DownloadSectionResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	if omci.Extended {
		if len(data) < 8 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		omci.Result = me.Results(data[6])
		omci.SectionNumber = data[7]
	} else {
		omci.Result = me.Results(data[4])
		omci.SectionNumber = data[5]
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeDownloadSectionResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.MsgLayerType = LayerTypeDownloadSectionResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeDownloadSectionResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.MsgLayerType = LayerTypeDownloadSectionResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Download Section Response message
func (omci *DownloadSectionResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Download section
	if !me.SupportsMsgType(meDefinition, me.DownloadSection) {
		return me.NewProcessingError("managed entity does not support Download Section Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Download Section response")
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	if omci.Extended {
		bytes, err := b.AppendBytes(4)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16(2))
		bytes[2] = byte(omci.Result)
		bytes[3] = omci.SectionNumber
	} else {
		bytes, err := b.AppendBytes(2)
		if err != nil {
			return err
		}
		bytes[0] = byte(omci.Result)
		bytes[1] = omci.SectionNumber
	}
	return nil
}

type EndSoftwareDownloadRequest struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	CRC32             uint32
	ImageSize         uint32
	NumberOfInstances byte
	ImageInstances    []uint16
}

func (omci *EndSoftwareDownloadRequest) String() string {
	return fmt.Sprintf("%v, CRC: %#x, Image Size: %v, Number of Instances: %v, Instances: %v",
		omci.MeBasePacket.String(), omci.CRC32, omci.ImageSize, omci.NumberOfInstances, omci.ImageInstances)
}

// LayerType returns LayerTypeEndSoftwareDownloadRequest
func (omci *EndSoftwareDownloadRequest) LayerType() gopacket.LayerType {
	return LayerTypeEndSoftwareDownloadRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *EndSoftwareDownloadRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeEndSoftwareDownloadRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *EndSoftwareDownloadRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of an End Software Download Request into this layer
func (omci *EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		hdrSize = 6 + 7
	} else {
		hdrSize = 4 + 7
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Software Download request")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.CRC32 = binary.BigEndian.Uint32(data[offset+4:])
	omci.ImageSize = binary.BigEndian.Uint32(data[offset+8:])
	omci.NumberOfInstances = data[offset+12]

	if omci.NumberOfInstances < 1 || omci.NumberOfInstances > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Instances: %v, must be 1..9",
			omci.NumberOfInstances))
	}
	omci.ImageInstances = make([]uint16, omci.NumberOfInstances)

	for index := 0; index < int(omci.NumberOfInstances); index++ {
		omci.ImageInstances[index] = binary.BigEndian.Uint16(data[offset+13+(index*2):])
	}
	return nil
}

func decodeEndSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeEndSoftwareDownloadRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an End Software Download Request message
func (omci *EndSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start End Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Software Download response")
	}
	if omci.NumberOfInstances < 1 || omci.NumberOfInstances > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Instances: %v, must be 1..9",
			omci.NumberOfInstances))
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 9 + (2 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(9+(2*int(omci.NumberOfInstances))))
	}
	binary.BigEndian.PutUint32(bytes[offset+0:], omci.CRC32)
	binary.BigEndian.PutUint32(bytes[offset+4:], omci.ImageSize)
	bytes[offset+8] = omci.NumberOfInstances
	for index := 0; index < int(omci.NumberOfInstances); index++ {
		binary.BigEndian.PutUint16(bytes[offset+9+(index*2):], omci.ImageInstances[index])
	}
	return nil
}

type EndSoftwareDownloadResponse struct {
	MeBasePacket      // Note: EntityInstance for software download is two specific values
	Result            me.Results
	NumberOfInstances byte
	MeResults         []DownloadResults
}

func (omci *EndSoftwareDownloadResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Number of Instances: %v, ME Results: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.NumberOfInstances, omci.MeResults)
}

// LayerType returns LayerTypeCreateResponse
func (omci *EndSoftwareDownloadResponse) LayerType() gopacket.LayerType {
	return LayerTypeEndSoftwareDownloadResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *EndSoftwareDownloadResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeEndSoftwareDownloadResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *EndSoftwareDownloadResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of an End Software Download Response into this layer
func (omci *EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Software Download response")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.Result = me.Results(data[offset+4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.NumberOfInstances = data[offset+5]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		omci.MeResults = make([]DownloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[offset+6+(index*3):])
			omci.MeResults[index].Result = me.Results(data[offset+8+(index*3)])
			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for End Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
		}
	}
	return nil
}

func decodeEndSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeEndSoftwareDownloadResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadResponse{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an End Software Download Response message
func (omci *EndSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End End Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Download response")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 2 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(2+(3*int(omci.NumberOfInstances))))
	}
	bytes[offset] = byte(omci.Result)
	bytes[offset+1] = omci.NumberOfInstances

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[offset+2+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for End Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[offset+4+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

type ActivateSoftwareRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	ActivateFlags byte
}

func (omci *ActivateSoftwareRequest) String() string {
	return fmt.Sprintf("%v, Flags: %#x",
		omci.MeBasePacket.String(), omci.ActivateFlags)
}

// LayerType returns LayerTypeActivateSoftwareRequest
func (omci *ActivateSoftwareRequest) LayerType() gopacket.LayerType {
	return LayerTypeActivateSoftwareRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *ActivateSoftwareRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeActivateSoftwareRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *ActivateSoftwareRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of an Activate Software Request into this layer
func (omci *ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software request")
	}
	if omci.Extended {
		omci.ActivateFlags = data[6]
	} else {
		omci.ActivateFlags = data[4]
	}
	if omci.ActivateFlags > 2 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Activation flangs: %v, must be 0..2",
			omci.ActivateFlags))
	}
	return nil
}

func decodeActivateSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareRequest{}
	omci.MsgLayerType = LayerTypeActivateSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeActivateSoftwareRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareRequest{}
	omci.MsgLayerType = LayerTypeActivateSoftwareRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Activate Software message
func (omci *ActivateSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software request")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 1)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(1))
	}
	bytes[offset] = omci.ActivateFlags
	if omci.ActivateFlags > 2 {
		msg := fmt.Sprintf("invalid results for Activate Software request: %v, must be 0..2",
			omci.ActivateFlags)
		return errors.New(msg)
	}
	return nil
}

type ActivateSoftwareResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *ActivateSoftwareResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// LayerType returns LayerTypeActivateSoftwareResponse
func (omci *ActivateSoftwareResponse) LayerType() gopacket.LayerType {
	return LayerTypeActivateSoftwareResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *ActivateSoftwareResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeActivateSoftwareResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *ActivateSoftwareResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of an Activate Software Response into this layer
func (omci *ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software response")
	}
	if omci.Extended {
		omci.Result = me.Results(data[6])
	} else {
		omci.Result = me.Results(data[4])
	}
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Activate Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeActivateSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareResponse{}
	omci.MsgLayerType = LayerTypeActivateSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeActivateSoftwareResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareResponse{}
	omci.MsgLayerType = LayerTypeActivateSoftwareResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Activate Software Response message
func (omci *ActivateSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software response")
	}
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Activate Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 1)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 1)
	}
	bytes[offset] = byte(omci.Result)
	return nil
}

type CommitSoftwareRequest struct {
	MeBasePacket
}

func (omci *CommitSoftwareRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// LayerType returns LayerTypeCommitSoftwareRequest
func (omci *CommitSoftwareRequest) LayerType() gopacket.LayerType {
	return LayerTypeCommitSoftwareRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *CommitSoftwareRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeCommitSoftwareRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *CommitSoftwareRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Commit Software Request into this layer
func (omci *CommitSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software request")
	}
	return nil
}

func decodeCommitSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareRequest{}
	omci.MsgLayerType = LayerTypeCommitSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeCommitSoftwareRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareRequest{}
	omci.MsgLayerType = LayerTypeCommitSoftwareRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Commit Software Request message
func (omci *CommitSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software request")
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

type CommitSoftwareResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *CommitSoftwareResponse) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// LayerType returns LayerTypeCommitSoftwareResponse
func (omci *CommitSoftwareResponse) LayerType() gopacket.LayerType {
	return LayerTypeCommitSoftwareResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *CommitSoftwareResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeCommitSoftwareResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *CommitSoftwareResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Commit Software Response into this layer
func (omci *CommitSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Commit Software
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software response")
	}
	if omci.Extended {
		omci.Result = me.Results(data[6])
	} else {
		omci.Result = me.Results(data[4])
	}
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Commit Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeCommitSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareResponse{}
	omci.MsgLayerType = LayerTypeCommitSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeCommitSoftwareResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareResponse{}
	omci.MsgLayerType = LayerTypeCommitSoftwareResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Commit Software Response message
func (omci *CommitSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Commit Software
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software response")
	}
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Commit Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 1)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 1)
		bytes[2] = byte(omci.Result)
	} else {
		bytes[0] = byte(omci.Result)
	}
	return nil
}
