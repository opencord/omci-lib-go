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

func decodeTestRequest(data []byte, p gopacket.PacketBuilder) error {
	// Peek at Managed Entity Type
	if len(data) < 8 {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	classID := binary.BigEndian.Uint16(data)

	// Is it a Managed Entity class we support customized decode of?
	switch me.ClassID(classID) {
	default:
		omci := &TestRequest{}
		omci.MsgLayerType = LayerTypeTestRequest
		return decodingLayerDecoder(omci, data, p)

	case me.AniGClassID, me.ReAniGClassID, me.PhysicalPathTerminationPointReUniClassID,
		me.ReUpstreamAmplifierClassID, me.ReDownstreamAmplifierClassID:
		omci := &OpticalLineSupervisionTestRequest{}
		omci.MsgLayerType = LayerTypeTestRequest
		return decodingLayerDecoder(omci, data, p)
	}
}

// TestRequest message
type TestRequest struct {
	MeBasePacket
	Payload []byte
}

func (omci *TestRequest) String() string {
	return fmt.Sprintf("%v, Request: %v octets", omci.MeBasePacket.String(), len(omci.Payload))
}

// LayerType returns LayerTypeTestRequest
func (omci *TestRequest) LayerType() gopacket.LayerType {
	return LayerTypeTestRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *TestRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeTestRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *TestRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (omci *TestRequest) TestRequest() []byte {
	return omci.Payload
}

// DecodeFromBytes decodes the given bytes of a Test Request into this layer
func (omci *TestRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
	if err != nil {
		return err
	}

	omci.Payload = make([]byte, MaxTestRequestLength)
	copy(omci.Payload, omci.MeBasePacket.Payload)
	return nil
}

// SerializeTo provides serialization of an Test Request message
func (omci *TestRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	if omci.Payload == nil {
		return errors.New("test results payload is missing")
	}

	if len(omci.Payload) > MaxTestRequestLength {
		msg := fmt.Sprintf("Invalid Test Request payload size. Received %v bytes, expected %v",
			len(omci.Payload), MaxTestRequestLength)
		return errors.New(msg)
	}
	bytes, err := b.AppendBytes(len(omci.Payload))
	if err != nil {
		return err
	}

	copy(bytes, omci.Payload)
	return nil
}

type OpticalLineSupervisionTestRequest struct {
	MeBasePacket
	SelectTest               uint8  // Bitfield
	GeneralPurposeBuffer     uint16 // Pointer to General Purpose Buffer ME
	VendorSpecificParameters uint16 // Pointer to Octet String ME
}

func (omci *OpticalLineSupervisionTestRequest) String() string {
	return fmt.Sprintf("Optical Line Supervision Test Result: SelectTest: %#x, Buffer: %#x, Params: %#x",
		omci.SelectTest, omci.GeneralPurposeBuffer, omci.VendorSpecificParameters)
}

// LayerType returns LayerTypeTestRequest
func (omci *OpticalLineSupervisionTestRequest) LayerType() gopacket.LayerType {
	return LayerTypeTestRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *OpticalLineSupervisionTestRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeTestRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *OpticalLineSupervisionTestRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (omci *OpticalLineSupervisionTestRequest) TestRequest() []byte {
	return omci.Payload
}

// DecodeFromBytes decodes the given bytes of a Test Result Notification into this layer
func (omci *OpticalLineSupervisionTestRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+5)
	if err != nil {
		return err
	}

	omci.SelectTest = data[4]
	omci.GeneralPurposeBuffer = binary.BigEndian.Uint16(data[5:])
	omci.VendorSpecificParameters = binary.BigEndian.Uint16(data[7:])
	return nil
}

// SerializeTo provides serialization of an Test Result notification message
func (omci *OpticalLineSupervisionTestRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}

	bytes, err := b.AppendBytes(8)
	if err != nil {
		return err
	}

	bytes[0] = omci.SelectTest
	binary.BigEndian.PutUint16(bytes[1:], omci.GeneralPurposeBuffer)
	binary.BigEndian.PutUint16(bytes[3:], omci.VendorSpecificParameters)
	return nil
}

// TestResponse message
type TestResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *TestResponse) String() string {
	return fmt.Sprintf("%v, Results: %d (%v)", omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// LayerType returns LayerTypeTestResponse
func (omci *TestResponse) LayerType() gopacket.LayerType {
	return LayerTypeTestResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *TestResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeTestResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *TestResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Test Response into this layer
func (omci *TestResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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

	// ME needs to support Test requests
	if !me.SupportsMsgType(meDefinition, me.Test) {
		return me.NewProcessingError("managed entity does not support Test Message-Type")
	}
	omci.Result = me.Results(data[4])
	return nil
}

func decodeTestResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestResponse{}
	omci.MsgLayerType = LayerTypeTestResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Test Response message
func (omci *TestResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(entity, me.Test) {
		return me.NewProcessingError("managed entity does not support the Test Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)

	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeTestResult(data []byte, p gopacket.PacketBuilder) error {
	// Peek at Managed Entity Type
	if len(data) < 8 {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	classID := binary.BigEndian.Uint16(data)

	// Is it a Managed Entity class we support customized decode of?
	switch me.ClassID(classID) {
	default:
		omci := &TestResultNotification{}
		omci.MsgLayerType = LayerTypeTestResult
		return decodingLayerDecoder(omci, data, p)

	case me.AniGClassID, me.ReAniGClassID, me.PhysicalPathTerminationPointReUniClassID,
		me.ReUpstreamAmplifierClassID, me.ReDownstreamAmplifierClassID:
		omci := &OpticalLineSupervisionTestResult{}
		omci.MsgLayerType = LayerTypeTestResult
		return decodingLayerDecoder(omci, data, p)
	}
}

func decodeTestResultExtended(data []byte, p gopacket.PacketBuilder) error {
	// Peek at Managed Entity Type
	if len(data) < 8 {
		p.SetTruncated()
		return errors.New("frame too small")
	}
	classID := binary.BigEndian.Uint16(data)

	// Is it a Managed Entity class we support customized decode of?
	switch me.ClassID(classID) {
	default:
		omci := &TestResultNotification{}
		omci.MsgLayerType = LayerTypeTestResult
		omci.Extended = true
		return decodingLayerDecoder(omci, data, p)

	case me.AniGClassID, me.ReAniGClassID, me.PhysicalPathTerminationPointReUniClassID,
		me.ReUpstreamAmplifierClassID, me.ReDownstreamAmplifierClassID:
		omci := &OpticalLineSupervisionTestResult{}
		omci.MsgLayerType = LayerTypeTestResult
		omci.Extended = true
		return decodingLayerDecoder(omci, data, p)
	}
}

type TestResultNotification struct {
	MeBasePacket
	Payload []byte
}

func (omci *TestResultNotification) TestResults() []byte {
	return omci.Payload
}

func (omci *TestResultNotification) String() string {
	return fmt.Sprintf("%v, Payload: %v octets", omci.MeBasePacket.String(), len(omci.Payload))
}

// LayerType returns LayerTypeTestResult
func (omci *TestResultNotification) LayerType() gopacket.LayerType {
	return LayerTypeTestResult
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *TestResultNotification) CanDecode() gopacket.LayerClass {
	return LayerTypeTestResult
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *TestResultNotification) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Test Result Notification into this layer
func (omci *TestResultNotification) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	payloadOffset := 4
	if omci.Extended {
		payloadOffset = 6
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, payloadOffset)
	if err != nil {
		return err
	}

	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}

	// ME needs to support Test requests
	if !me.SupportsMsgType(meDefinition, me.Test) {
		return me.NewProcessingError("managed entity does not support Test Message-Type")
	}
	if omci.Extended {
		if len(data) < 6 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		length := binary.BigEndian.Uint16(data[4:])
		if len(data) < 6+int(length) {
			p.SetTruncated()
			return errors.New("frame too small")
		}
		omci.Payload = make([]byte, length)
		copy(omci.Payload, data[6:])
	} else {
		omci.Payload = make([]byte, MaxTestResultsLength)
		copy(omci.Payload, omci.MeBasePacket.Payload)
	}
	return nil
}

// SerializeTo provides serialization of an Test Result notification message
func (omci *TestResultNotification) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}

	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}

	// ME needs to support Test requests
	if !me.SupportsMsgType(meDefinition, me.Test) {
		return me.NewProcessingError("managed entity does not support Test Message-Type")
	}
	if omci.Payload == nil {
		return errors.New("test results payload is missing")
	}

	payloadOffset := 0
	maxSize := MaxTestResultsLength

	if omci.Extended {
		payloadOffset = 2
		maxSize = MaxExtendedLength - 10 - 4
	}
	if len(omci.Payload) > maxSize {
		msg := fmt.Sprintf("Invalid Test Results payload size. Received %v bytes, max expected %v",
			len(omci.Payload), maxSize)
		return errors.New(msg)
	}
	bytes, err := b.AppendBytes(len(omci.Payload) + payloadOffset)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(len(omci.Payload)))
	}
	copy(bytes[payloadOffset:], omci.Payload)
	return nil
}

// OpticalLineSupervisionTestResult provides a Optical Specific test results
// message decode for the associated Managed Entities
type OpticalLineSupervisionTestResult struct {
	MeBasePacket
	PowerFeedVoltageType     uint8  // Type = 1
	PowerFeedVoltage         uint16 // value
	ReceivedOpticalPowerType uint8  // Type = 3
	ReceivedOpticalPower     uint16 // value
	MeanOpticalLaunchType    uint8  // Type = 5
	MeanOpticalLaunch        uint16 // value
	LaserBiasCurrentType     uint8  // Type = 9
	LaserBiasCurrent         uint16 // value
	TemperatureType          uint8  // Type = 12
	Temperature              uint16 // value

	GeneralPurposeBuffer uint16 // Pointer to General Purpose Buffer ME
}

func (omci *OpticalLineSupervisionTestResult) String() string {
	return fmt.Sprintf("Optical Line Supervision Test Result")
}

// LayerType returns LayerTypeTestResult
func (omci *OpticalLineSupervisionTestResult) LayerType() gopacket.LayerType {
	return LayerTypeTestResult
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *OpticalLineSupervisionTestResult) CanDecode() gopacket.LayerClass {
	return LayerTypeTestResult
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *OpticalLineSupervisionTestResult) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (omci *OpticalLineSupervisionTestResult) TestResults() []byte {
	return omci.MeBasePacket.Payload
}

// DecodeFromBytes decodes the given bytes of a Test Result Notification into this layer
func (omci *OpticalLineSupervisionTestResult) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	payloadOffset := 4
	if omci.Extended {
		payloadOffset = 6
	}
	err := omci.MeBasePacket.DecodeFromBytes(data, p, payloadOffset+17)
	if err != nil {
		return err
	}

	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}

	// ME needs to support Test requests
	if !me.SupportsMsgType(meDefinition, me.Test) {
		return me.NewProcessingError("managed entity does not support Test Message-Type")
	}
	// Note: Unsupported tests will have a type = 0 and the value should be zero
	//       as well, but that constraint is not enforced at this time.
	// Type = 1
	omci.PowerFeedVoltageType = data[payloadOffset]
	omci.PowerFeedVoltage = binary.BigEndian.Uint16(data[payloadOffset+1:])

	// Type = 3
	omci.ReceivedOpticalPowerType = data[payloadOffset+3]
	omci.ReceivedOpticalPower = binary.BigEndian.Uint16(data[payloadOffset+4:])

	// Type = 5
	omci.MeanOpticalLaunchType = data[payloadOffset+6]
	omci.MeanOpticalLaunch = binary.BigEndian.Uint16(data[payloadOffset+7:])

	// Type = 9
	omci.LaserBiasCurrentType = data[payloadOffset+9]
	omci.LaserBiasCurrent = binary.BigEndian.Uint16(data[payloadOffset+10:])

	// Type = 12
	omci.TemperatureType = data[payloadOffset+12]
	omci.Temperature = binary.BigEndian.Uint16(data[payloadOffset+13:])

	omci.GeneralPurposeBuffer = binary.BigEndian.Uint16(data[payloadOffset+15:])
	return nil
}

// SerializeTo provides serialization of an Test Result notification message
func (omci *OpticalLineSupervisionTestResult) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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

	// ME needs to support Test requests
	if !me.SupportsMsgType(meDefinition, me.Test) {
		return me.NewProcessingError("managed entity does not support Test Message-Type")
	}
	payloadOffset := 0

	if omci.Extended {
		payloadOffset = 2
	}
	bytes, err := b.AppendBytes(payloadOffset + 17)
	if err != nil {
		return err
	}

	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, 17)
	}
	bytes[payloadOffset] = omci.PowerFeedVoltageType
	binary.BigEndian.PutUint16(bytes[payloadOffset+1:], omci.PowerFeedVoltage)
	bytes[payloadOffset+3] = omci.ReceivedOpticalPowerType
	binary.BigEndian.PutUint16(bytes[payloadOffset+4:], omci.ReceivedOpticalPower)
	bytes[payloadOffset+6] = omci.MeanOpticalLaunchType
	binary.BigEndian.PutUint16(bytes[payloadOffset+7:], omci.MeanOpticalLaunch)
	bytes[payloadOffset+9] = omci.LaserBiasCurrentType
	binary.BigEndian.PutUint16(bytes[payloadOffset+10:], omci.LaserBiasCurrent)
	bytes[payloadOffset+12] = omci.TemperatureType
	binary.BigEndian.PutUint16(bytes[payloadOffset+13:], omci.Temperature)
	binary.BigEndian.PutUint16(bytes[payloadOffset+15:], omci.GeneralPurposeBuffer)
	return nil
}
