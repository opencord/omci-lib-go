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

type GetAllAlarmsRequest struct {
	MeBasePacket
	AlarmRetrievalMode byte
}

func (omci *GetAllAlarmsRequest) String() string {
	return fmt.Sprintf("%v, Retrieval Mode: %v",
		omci.MeBasePacket.String(), omci.AlarmRetrievalMode)
}

// LayerType returns LayerTypeGetAllAlarmsRequest
func (omci *GetAllAlarmsRequest) LayerType() gopacket.LayerType {
	return LayerTypeGetAllAlarmsRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetAllAlarmsRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeGetAllAlarmsRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetAllAlarmsRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Request into this layer
func (omci *GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		//start here
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.AlarmRetrievalMode = data[4+offset]
	if omci.AlarmRetrievalMode > 1 {
		msg := fmt.Sprintf("invalid Alarm Retrieval Mode for Get All Alarms request: %v, must be 0..1",
			omci.AlarmRetrievalMode)
		return errors.New(msg)
	}
	return nil
}

func decodeGetAllAlarmsRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetAllAlarmsRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Request message
func (omci *GetAllAlarmsRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(entity, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Message-Type")
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
	bytes[offset] = omci.AlarmRetrievalMode
	return nil
}

type GetAllAlarmsResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *GetAllAlarmsResponse) String() string {
	return fmt.Sprintf("%v, NumberOfCommands: %d",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

// LayerType returns LayerTypeGetAllAlarmsResponse
func (omci *GetAllAlarmsResponse) LayerType() gopacket.LayerType {
	return LayerTypeGetAllAlarmsResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetAllAlarmsResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeGetAllAlarmsResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetAllAlarmsResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Response into this layer
func (omci *GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		//start here
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.NumberOfCommands = binary.BigEndian.Uint16(data[4+offset:])
	return nil
}

func decodeGetAllAlarmsResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetAllAlarmsResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Response message
func (omci *GetAllAlarmsResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(entity, me.GetAllAlarms) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 2)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(2))
	}
	binary.BigEndian.PutUint16(bytes[offset:], omci.NumberOfCommands)
	return nil
}

type GetAllAlarmsNextRequest struct {
	MeBasePacket
	CommandSequenceNumber uint16
}

func (omci *GetAllAlarmsNextRequest) String() string {
	return fmt.Sprintf("%v, Sequence Number: %d",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

// LayerType returns LayerTypeGetAllAlarmsNextRequest
func (omci *GetAllAlarmsNextRequest) LayerType() gopacket.LayerType {
	return LayerTypeGetAllAlarmsNextRequest
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetAllAlarmsNextRequest) CanDecode() gopacket.LayerClass {
	return LayerTypeGetAllAlarmsNextRequest
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetAllAlarmsNextRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Next Request into this layer
func (omci *GetAllAlarmsNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	var hdrSize int
	if omci.Extended {
		//start here
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms Next request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms Next request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	omci.CommandSequenceNumber = binary.BigEndian.Uint16(data[4+offset:])
	return nil
}

func decodeGetAllAlarmsNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextRequest
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetAllAlarmsNextRequestExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextRequest
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Next Request message
func (omci *GetAllAlarmsNextRequest) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(entity, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Next Message-Type")
	}
	var offset int
	if omci.Extended {
		offset = 2
	}
	bytes, err := b.AppendBytes(offset + 2)
	if err != nil {
		return err
	}
	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(2))
	}
	binary.BigEndian.PutUint16(bytes[offset:], omci.CommandSequenceNumber)
	return nil
}

type AdditionalAlarmsData struct {
	AlarmEntityClass    me.ClassID
	AlarmEntityInstance uint16
	AlarmBitMap         [28]byte // 224 bits
}

type GetAllAlarmsNextResponse struct {
	MeBasePacket
	AlarmEntityClass    me.ClassID
	AlarmEntityInstance uint16
	AlarmBitMap         [28]byte               // 224 bits
	AdditionalAlarms    []AdditionalAlarmsData // Valid only for extended message set version
}

func (omci *GetAllAlarmsNextResponse) String() string {
	return fmt.Sprintf("%v, CID: %v, EID: (%d/%#x), Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmEntityClass, omci.AlarmEntityInstance,
		omci.AlarmEntityInstance, omci.AlarmBitMap)
}

// LayerType returns LayerTypeGetAllAlarmsNextResponse
func (omci *GetAllAlarmsNextResponse) LayerType() gopacket.LayerType {
	return LayerTypeGetAllAlarmsNextResponse
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *GetAllAlarmsNextResponse) CanDecode() gopacket.LayerClass {
	return LayerTypeGetAllAlarmsNextResponse
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *GetAllAlarmsNextResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Next Response into this layer
func (omci *GetAllAlarmsNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(meDefinition, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support Get All Alarms Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for Get All Alarms Next response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for Get All Alarms Next response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	//err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+4+28)	// Decode reported ME.  If an out-of-range sequence number was sent, this will
	//	// contain an ME with class ID and entity ID of zero and you should get an
	//	// error of "managed entity definition not found" returned.
	var offset int
	msgContentsLen := 28
	if omci.Extended {
		offset = 2 // Message Contents length (2)
		msgContentsLen = int(binary.BigEndian.Uint16(data[6:]))
	}
	if len(data[4+offset:]) < 4+msgContentsLen {
		p.SetTruncated()
		return errors.New("frame too small: Get All Alarms Next Response Managed Entity attribute truncated")
	}
	omci.AlarmEntityClass = me.ClassID(binary.BigEndian.Uint16(data[4+offset:]))
	omci.AlarmEntityInstance = binary.BigEndian.Uint16(data[6+offset:])

	copy(omci.AlarmBitMap[:], data[8+offset:36])
	remaining := len(data) - (6 + 4 + 28)

	if !omci.Extended || remaining <= 0 {
		return nil
	}
	offset = 6 + 4 + 28
	omci.AdditionalAlarms = make([]AdditionalAlarmsData, 0)
	for remaining > 0 {
		if remaining < 4+28 {
			p.SetTruncated()
			return errors.New("frame too small: Get All Alarms Next Response Managed Entity attribute truncated")
		}
		alarm := AdditionalAlarmsData{
			AlarmEntityClass:    me.ClassID(binary.BigEndian.Uint16(data[offset:])),
			AlarmEntityInstance: binary.BigEndian.Uint16(data[offset+2:]),
		}
		copy(alarm.AlarmBitMap[:], data[offset+4:])
		omci.AdditionalAlarms = append(omci.AdditionalAlarms, alarm)

		offset += 4 + 28
		remaining -= 4 + 28
	}
	return nil
}

func decodeGetAllAlarmsNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextResponse
	return decodingLayerDecoder(omci, data, p)
}

func decodeGetAllAlarmsNextResponseExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextResponse
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Next Response message
func (omci *GetAllAlarmsNextResponse) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
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
	// ME needs to support Get All Alarms Next
	if !me.SupportsMsgType(entity, me.GetAllAlarmsNext) {
		return me.NewProcessingError("managed entity does not support the Get All Alarms Next Message-Type")
	}
	contentLength := 2 + 2 + 28
	maxLength := MaxBaselineLength - 8 - 8
	var extraMEs int
	var offset int

	if omci.Extended {
		maxLength = MaxExtendedLength - 10 - 4
		offset = 2
		contentLength += 2 // Length field
		if omci.AdditionalAlarms != nil {
			extraMEs = len(omci.AdditionalAlarms)
			contentLength += extraMEs*4 + 28
		}
	}
	if contentLength > maxLength {
		msg := fmt.Sprintf("not enough space to fit all requested Managed Entities, have %v, requested: %v",
			maxLength, contentLength)
		return me.NewMessageTruncatedError(msg)
	}
	// Allocate space for all
	bytes, err := b.AppendBytes(contentLength)
	if err != nil {
		return err
	}
	// Always encode the first ME alarm data
	binary.BigEndian.PutUint16(bytes[offset:], uint16(omci.AlarmEntityClass))
	binary.BigEndian.PutUint16(bytes[offset+2:], omci.AlarmEntityInstance)
	copy(bytes[offset+4:], omci.AlarmBitMap[:])

	if omci.Extended {
		binary.BigEndian.PutUint16(bytes, uint16(contentLength-2))

		if omci.AdditionalAlarms != nil {
			for index, value := range omci.AdditionalAlarms {
				offset = (32 * (index + 1)) + 2
				binary.BigEndian.PutUint16(bytes[offset:], uint16(value.AlarmEntityClass))
				binary.BigEndian.PutUint16(bytes[offset+2:], value.AlarmEntityInstance)
				copy(bytes[offset+4:], value.AlarmBitMap[:])
			}
		}
	}
	return nil
}

const AlarmBitmapSize = 224

type AlarmNotificationMsg struct {
	MeBasePacket
	AlarmBitmap         [AlarmBitmapSize / 8]byte
	zeroPadding         [3]byte // Note: This zero padding is not present in the Extended Message Set
	AlarmSequenceNumber byte
}

func (omci *AlarmNotificationMsg) String() string {
	return fmt.Sprintf("%v, Sequence Number: %d, Alarm Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmSequenceNumber, omci.AlarmBitmap)
}

// LayerType returns LayerTypeAlarmNotification
func (omci *AlarmNotificationMsg) LayerType() gopacket.LayerType {
	return LayerTypeAlarmNotification
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (omci *AlarmNotificationMsg) CanDecode() gopacket.LayerClass {
	return LayerTypeAlarmNotification
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *AlarmNotificationMsg) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (omci *AlarmNotificationMsg) IsAlarmActive(alarmNumber uint8) (bool, error) {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return false, errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return false, omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		msg := "managed entity does not support Alarm notifications"
		return false, errors.New(msg)
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return false, errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	return omci.AlarmBitmap[octet]>>bit == 1, nil
}

func (omci *AlarmNotificationMsg) IsAlarmClear(alarmNumber uint8) (bool, error) {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return false, errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return false, omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		return false, errors.New("managed entity does not support Alarm notifications")
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return false, errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	return omci.AlarmBitmap[octet]>>bit == 0, nil
}

func (omci *AlarmNotificationMsg) ActivateAlarm(alarmNumber uint8) error {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		return errors.New("managed entity does not support Alarm notifications")
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	omci.AlarmBitmap[octet] |= 1 << bit
	return nil
}

func (omci *AlarmNotificationMsg) ClearAlarm(alarmNumber uint8) error {
	if alarmNumber >= AlarmBitmapSize {
		msg := fmt.Sprintf("invalid alarm number: %v, must be 0..224", alarmNumber)
		return errors.New(msg)
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	alarmMap := entity.GetAlarmMap()
	if alarmMap == nil {
		return errors.New("managed entity does not support Alarm notifications")
	}
	if _, ok := alarmMap[alarmNumber]; !ok {
		msg := fmt.Sprintf("unsupported invalid alarm number: %v", alarmNumber)
		return errors.New(msg)
	}
	octet := alarmNumber / 8
	bit := 7 - (alarmNumber % 8)
	omci.AlarmBitmap[octet] &= ^(1 << bit)
	return nil
}

// DecodeFromBytes decodes the given bytes of an Alarm Notification into this layer
func (omci *AlarmNotificationMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+28)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// Is this an unsupported or vendor specific ME.  If so, it is not an error to decode
	// the alarms.  We just cannot provide any alarm names.  Handle decode here.
	classSupport := meDefinition.GetClassSupport()
	isUnsupported := classSupport == me.UnsupportedManagedEntity ||
		classSupport == me.UnsupportedVendorSpecificManagedEntity

	mapOffset := 4
	if omci.Extended {
		mapOffset = 6
		if len(data) < 6+28+1 {
			p.SetTruncated()
			return errors.New("frame too small")
		}
	}
	// Look for a non-nil/not empty Alarm Map to determine if this ME supports alarms
	if alarmMap := meDefinition.GetAlarmMap(); isUnsupported || (alarmMap != nil && len(alarmMap) > 0) {
		for index, octet := range data[mapOffset : (AlarmBitmapSize/8)-mapOffset] {
			omci.AlarmBitmap[index] = octet
		}
		if omci.Extended {
			omci.AlarmSequenceNumber = data[mapOffset+(AlarmBitmapSize/8)]
		} else {
			padOffset := mapOffset + (AlarmBitmapSize / 8)
			omci.zeroPadding[0] = data[padOffset]
			omci.zeroPadding[1] = data[padOffset+1]
			omci.zeroPadding[2] = data[padOffset+2]
			omci.AlarmSequenceNumber = data[padOffset+3]
		}
		return nil
	}
	return me.NewProcessingError("managed entity does not support alarm notifications")
}

func decodeAlarmNotification(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.MsgLayerType = LayerTypeAlarmNotification
	return decodingLayerDecoder(omci, data, p)
}

func decodeAlarmNotificationExtended(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.MsgLayerType = LayerTypeAlarmNotification
	omci.Extended = true
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Alarm Notification message
func (omci *AlarmNotificationMsg) SerializeTo(b gopacket.SerializeBuffer, _ gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	// TODO: Support of encoding AlarmNotification into supported types not yet supported
	//meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
	//	me.ParamData{EntityID: omci.EntityInstance})
	//if omciErr.StatusCode() != me.Success {
	//	return omciErr.GetError()
	//}
	//if !me.SupportsMsgType(meDefinition, me.AlarmNotification) {
	//	return me.NewProcessingError("managed entity does not support Alarm Notification Message-Type")
	//}
	if omci.Extended {
		bytes, err := b.AppendBytes(2 + (AlarmBitmapSize / 8) + 1)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes, uint16((AlarmBitmapSize/8)+1))

		for index, octet := range omci.AlarmBitmap {
			bytes[2+index] = octet
		}
		bytes[2+(AlarmBitmapSize/8)] = omci.AlarmSequenceNumber
	} else {
		bytes, err := b.AppendBytes((AlarmBitmapSize / 8) + 3 + 1)
		if err != nil {
			return err
		}
		for index, octet := range omci.AlarmBitmap {
			bytes[index] = octet
		}
		padOffset := AlarmBitmapSize / 8
		bytes[padOffset] = 0
		bytes[padOffset+1] = 0
		bytes[padOffset+2] = 0
		bytes[padOffset+3] = omci.AlarmSequenceNumber
	}
	return nil
}
