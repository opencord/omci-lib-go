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
	me "github.com/opencord/omci-lib-go/generated"
)

// MessageType is the OMCI Message Type or'ed with the AR/AK flags as appropriate.
type MessageType byte

const (
	CreateRequestType                      = MessageType(byte(me.Create) | me.AR)
	CreateResponseType                     = MessageType(byte(me.Create) | me.AK)
	DeleteRequestType                      = MessageType(byte(me.Delete) | me.AR)
	DeleteResponseType                     = MessageType(byte(me.Delete) | me.AK)
	SetRequestType                         = MessageType(byte(me.Set) | me.AR)
	SetResponseType                        = MessageType(byte(me.Set) | me.AK)
	GetRequestType                         = MessageType(byte(me.Get) | me.AR)
	GetResponseType                        = MessageType(byte(me.Get) | me.AK)
	GetAllAlarmsRequestType                = MessageType(byte(me.GetAllAlarms) | me.AR)
	GetAllAlarmsResponseType               = MessageType(byte(me.GetAllAlarms) | me.AK)
	GetAllAlarmsNextRequestType            = MessageType(byte(me.GetAllAlarmsNext) | me.AR)
	GetAllAlarmsNextResponseType           = MessageType(byte(me.GetAllAlarmsNext) | me.AK)
	MibUploadRequestType                   = MessageType(byte(me.MibUpload) | me.AR)
	MibUploadResponseType                  = MessageType(byte(me.MibUpload) | me.AK)
	MibUploadNextRequestType               = MessageType(byte(me.MibUploadNext) | me.AR)
	MibUploadNextResponseType              = MessageType(byte(me.MibUploadNext) | me.AK)
	MibResetRequestType                    = MessageType(byte(me.MibReset) | me.AR)
	MibResetResponseType                   = MessageType(byte(me.MibReset) | me.AK)
	TestRequestType                        = MessageType(byte(me.Test) | me.AR)
	TestResponseType                       = MessageType(byte(me.Test) | me.AK)
	StartSoftwareDownloadRequestType       = MessageType(byte(me.StartSoftwareDownload) | me.AR)
	StartSoftwareDownloadResponseType      = MessageType(byte(me.StartSoftwareDownload) | me.AK)
	DownloadSectionRequestType             = MessageType(me.DownloadSection) // me.AR is optional
	DownloadSectionRequestWithResponseType = MessageType(byte(me.DownloadSection) | me.AR)
	DownloadSectionResponseType            = MessageType(byte(me.DownloadSection) | me.AK)
	EndSoftwareDownloadRequestType         = MessageType(byte(me.EndSoftwareDownload) | me.AR)
	EndSoftwareDownloadResponseType        = MessageType(byte(me.EndSoftwareDownload) | me.AK)
	ActivateSoftwareRequestType            = MessageType(byte(me.ActivateSoftware) | me.AR)
	ActivateSoftwareResponseType           = MessageType(byte(me.ActivateSoftware) | me.AK)
	CommitSoftwareRequestType              = MessageType(byte(me.CommitSoftware) | me.AR)
	CommitSoftwareResponseType             = MessageType(byte(me.CommitSoftware) | me.AK)
	SynchronizeTimeRequestType             = MessageType(byte(me.SynchronizeTime) | me.AR)
	SynchronizeTimeResponseType            = MessageType(byte(me.SynchronizeTime) | me.AK)
	RebootRequestType                      = MessageType(byte(me.Reboot) | me.AR)
	RebootResponseType                     = MessageType(byte(me.Reboot) | me.AK)
	GetNextRequestType                     = MessageType(byte(me.GetNext) | me.AR)
	GetNextResponseType                    = MessageType(byte(me.GetNext) | me.AK)
	GetCurrentDataRequestType              = MessageType(byte(me.GetCurrentData) | me.AR)
	GetCurrentDataResponseType             = MessageType(byte(me.GetCurrentData) | me.AK)
	SetTableRequestType                    = MessageType(byte(me.SetTable) | me.AR)
	SetTableResponseType                   = MessageType(byte(me.SetTable) | me.AK)

	// Autonomous ONU messages
	AlarmNotificationType    = MessageType(byte(me.AlarmNotification))
	AttributeValueChangeType = MessageType(byte(me.AttributeValueChange))
	TestResultType           = MessageType(byte(me.TestResult))

	// Support mapping of extended format types (use MSB reserved bit)
	ExtendedTypeDecodeOffset = MessageType(byte(0x80))
)

func (mt MessageType) String() string {
	switch mt {
	default:
		return "Unknown"

	case CreateRequestType:
		return "Create Request"
	case CreateResponseType:
		return "Create Response"
	case DeleteRequestType:
		return "Delete Request"
	case DeleteResponseType:
		return "Delete Response"
	case SetRequestType:
		return "Set Request"
	case SetResponseType:
		return "Set Response"
	case GetRequestType:
		return "Get Request"
	case GetResponseType:
		return "Get Response"
	case GetAllAlarmsRequestType:
		return "Get All Alarms Request"
	case GetAllAlarmsResponseType:
		return "Get All Alarms Response"
	case GetAllAlarmsNextRequestType:
		return "Get All Alarms Next Request"
	case GetAllAlarmsNextResponseType:
		return "Get All Alarms Next Response"
	case MibUploadRequestType:
		return "MIB Upload Request"
	case MibUploadResponseType:
		return "MIB Upload Response"
	case MibUploadNextRequestType:
		return "MIB Upload Next Request"
	case MibUploadNextResponseType:
		return "MIB Upload Next Response"
	case MibResetRequestType:
		return "MIB Reset Request"
	case MibResetResponseType:
		return "MIB Reset Response"
	case TestRequestType:
		return "Test Request"
	case TestResponseType:
		return "Test Response"
	case StartSoftwareDownloadRequestType:
		return "Start Software Download Request"
	case StartSoftwareDownloadResponseType:
		return "Start Software Download Response"
	case DownloadSectionRequestType, DownloadSectionRequestWithResponseType:
		return "Download Section Request"
	case DownloadSectionResponseType:
		return "Download Section Response"
	case EndSoftwareDownloadRequestType:
		return "End Software Download Request"
	case EndSoftwareDownloadResponseType:
		return "End Software Download Response"
	case ActivateSoftwareRequestType:
		return "Activate Software Request"
	case ActivateSoftwareResponseType:
		return "Activate Software Response"
	case CommitSoftwareRequestType:
		return "Commit Software Request"
	case CommitSoftwareResponseType:
		return "Commit Software Response"
	case SynchronizeTimeRequestType:
		return "Synchronize Time Request"
	case SynchronizeTimeResponseType:
		return "Synchronize Time Response"
	case RebootRequestType:
		return "Reboot Request"
	case RebootResponseType:
		return "Reboot Response"
	case GetNextRequestType:
		return "Get Next Request"
	case GetNextResponseType:
		return "Get Next Response"
	case GetCurrentDataRequestType:
		return "Get Current Data Request"
	case GetCurrentDataResponseType:
		return "Get Current Data Response"
	case SetTableRequestType:
		return "Set Table Request"
	case SetTableResponseType:
		return "Set Table Response"
	case AlarmNotificationType:
		return "Alarm Notification"
	case AttributeValueChangeType:
		return "Attribute Value Change"
	case TestResultType:
		return "Test Result"
	}
}

/////////////////////////////////////////////////////////////////////////////
// CreateRequest
type CreateRequest struct {
	MeBasePacket
	Attributes me.AttributeValueMap
}

func (omci *CreateRequest) String() string {
	return fmt.Sprintf("%v, attributes: %v", omci.MeBasePacket.String(), omci.Attributes)
}

// DecodeFromBytes decodes the given bytes of a Create Request into this layer
func (omci *CreateRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
	if err != nil {
		return err
	}
	// Create attribute mask for all set-by-create entries
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Create
	if !me.SupportsMsgType(meDefinition, me.Create) {
		return me.NewProcessingError("managed entity does not support Create Message-Type")
	}
	var sbcMask uint16
	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if me.SupportsAttributeAccess(attr, me.SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= attr.Mask
		}
	}
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(sbcMask, data[4:], p, byte(CreateRequestType))
	if err != nil {
		return err
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	panic("All Managed Entities have an EntityID attribute")
}

func decodeCreateRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateRequest{}
	omci.MsgLayerType = LayerTypeCreateRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Create Request Message
func (omci *CreateRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// Create attribute mask of SetByCreate attributes that should be present in the provided
	// attributes.
	var sbcMask uint16
	for index, attr := range meDefinition.GetAttributeDefinitions() {
		if me.SupportsAttributeAccess(attr, me.SetByCreate) {
			if index == 0 {
				continue // Skip Entity ID
			}
			sbcMask |= attr.Mask
		}
	}
	// Attribute serialization
	// TODO: Only Baseline supported at this time
	bytesAvailable := MaxBaselineLength - 8 - 8
	err, _ = meDefinition.SerializeAttributes(omci.Attributes, sbcMask, b, byte(CreateRequestType), bytesAvailable, false)
	return err
}

/////////////////////////////////////////////////////////////////////////////
// CreateResponse
type CreateResponse struct {
	MeBasePacket
	Result                 me.Results
	AttributeExecutionMask uint16 // Used when Result == ParameterError
}

func (omci *CreateResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Mask: %#x",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.AttributeExecutionMask)
}

// DecodeFromBytes decodes the given bytes of a Create Response into this layer
func (omci *CreateResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+3)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Create
	if !me.SupportsMsgType(entity, me.Create) {
		return me.NewProcessingError("managed entity does not support the Create Message-Type")
	}
	omci.Result = me.Results(data[4])
	if omci.Result == me.ParameterError {
		omci.AttributeExecutionMask = binary.BigEndian.Uint16(data[5:])
		// TODO: validation that attributes set in mask are SetByCreate would be good here
	}
	return nil
}

func decodeCreateResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateResponse{}
	omci.MsgLayerType = LayerTypeCreateResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Create Response message
func (omci *CreateResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support Create
	if !me.SupportsMsgType(entity, me.Create) {
		return me.NewProcessingError("managed entity does not support the Create Message-Type")
	}
	bytes, err := b.AppendBytes(3)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result == me.ParameterError {
		// TODO: validation that attributes set in mask are SetByCreate would be good here
		binary.BigEndian.PutUint16(bytes[1:], omci.AttributeExecutionMask)
	} else {
		binary.BigEndian.PutUint16(bytes[1:], 0)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// DeleteRequest
type DeleteRequest struct {
	MeBasePacket
}

func (omci *DeleteRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Delete Request into this layer
func (omci *DeleteRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
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

// SerializeTo provides serialization of an Delete Request message
func (omci *DeleteRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// DeleteResponse
type DeleteResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *DeleteResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// DecodeFromBytes decodes the given bytes of a Delete Response into this layer
func (omci *DeleteResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+1)
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
	omci.Result = me.Results(data[4])
	return nil
}

func decodeDeleteResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteResponse{}
	omci.MsgLayerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Delete Response message
func (omci *DeleteResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// SetRequest
type SetRequest struct {
	MeBasePacket
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *SetRequest) String() string {
	return fmt.Sprintf("%v, Mask: %#x, attributes: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.Attributes)
}

// DecodeFromBytes decodes the given bytes of a Set Request into this layer
func (omci *SetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.Set) {
		return me.NewProcessingError("managed entity does not support Set Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:], p, byte(SetRequestType))
	if err != nil {
		return err
	}
	// Validate all attributes support write
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Write) {
			msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	if eidDef, eidDefOK := meDefinition.GetAttributeDefinitions()[0]; eidDefOK {
		omci.Attributes[eidDef.GetName()] = omci.EntityInstance
		return nil
	}
	panic("All Managed Entities have an EntityID attribute")
}

func decodeSetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetRequest{}
	omci.MsgLayerType = LayerTypeSetRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Request message
func (omci *SetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(meDefinition, me.Set) {
		return me.NewProcessingError("managed entity does not support Set Message-Type")
	}
	// Validate all attributes support write
	for attrName := range omci.Attributes {
		attr, err := me.GetAttributeDefinitionByName(meDefinition.GetAttributeDefinitions(), attrName)
		if err != nil {
			return err
		}
		// Do not test for write of Entity ID in the attribute list
		if attr.Index != 0 && !me.SupportsAttributeAccess(*attr, me.Write) {
			// TODO: Check ITU spec to see if this should be listed as a failed
			//       attribute and not a processing error.
			msg := fmt.Sprintf("attribute '%v' does not support write access", attrName)
			return me.NewProcessingError(msg)
		}
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)

	// Attribute serialization
	// TODO: Only Baseline supported at this time
	bytesAvailable := MaxBaselineLength - 10 - 8

	err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b,
		byte(SetRequestType), bytesAvailable, false)
	return err
}

/////////////////////////////////////////////////////////////////////////////
// SetResponse
type SetResponse struct {
	MeBasePacket
	Result                   me.Results
	UnsupportedAttributeMask uint16
	FailedAttributeMask      uint16
}

func (omci *SetResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Unsupported Mask: %#x, Failed Mask: %#x",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.UnsupportedAttributeMask,
		omci.FailedAttributeMask)
}

// DecodeFromBytes decodes the given bytes of a Set Response into this layer
func (omci *SetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+5)
	if err != nil {
		return err
	}
	entity, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Set
	if !me.SupportsMsgType(entity, me.Set) {
		return me.NewProcessingError("managed entity does not support the Delete Message-Type")
	}
	omci.Result = me.Results(data[4])

	if omci.Result == me.AttributeFailure {
		omci.UnsupportedAttributeMask = binary.BigEndian.Uint16(data[5:7])
		omci.FailedAttributeMask = binary.BigEndian.Uint16(data[7:9])
	}
	return nil
}

func decodeSetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetResponse{}
	omci.MsgLayerType = LayerTypeSetResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Response message
func (omci *SetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(entity, me.Set) {
		return me.NewProcessingError("managed entity does not support the Set Message-Type")
	}
	bytes, err := b.AppendBytes(5)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	binary.BigEndian.PutUint16(bytes[1:3], omci.UnsupportedAttributeMask)
	binary.BigEndian.PutUint16(bytes[3:5], omci.FailedAttributeMask)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetRequest
type GetRequest struct {
	MeBasePacket
	AttributeMask uint16
}

func (omci *GetRequest) String() string {
	return fmt.Sprintf("%v, Mask: %#x",
		omci.MeBasePacket.String(), omci.AttributeMask)
}

// DecodeFromBytes decodes the given bytes of a Get Request into this layer
func (omci *GetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
func (omci *GetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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

func (omci *GetRequest) SerializeToExtended(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetResponse
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
	panic("All Managed Entities have an EntityID attribute")
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

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsRequest struct {
	MeBasePacket
	AlarmRetrievalMode byte
}

func (omci *GetAllAlarmsRequest) String() string {
	return fmt.Sprintf("%v, Retrieval Mode: %v",
		omci.MeBasePacket.String(), omci.AlarmRetrievalMode)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Request into this layer
func (omci *GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	omci.AlarmRetrievalMode = data[4]
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

// SerializeTo provides serialization of an Get All Alarms Request message
func (omci *GetAllAlarmsRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = omci.AlarmRetrievalMode
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *GetAllAlarmsResponse) String() string {
	return fmt.Sprintf("%v, NumberOfCommands: %d",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Response into this layer
func (omci *GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	omci.NumberOfCommands = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetAllAlarmsResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Response message
func (omci *GetAllAlarmsResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.NumberOfCommands)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsNextRequest struct {
	MeBasePacket
	CommandSequenceNumber uint16
}

func (omci *GetAllAlarmsNextRequest) String() string {
	return fmt.Sprintf("%v, Sequence Number: %d",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Next Request into this layer
func (omci *GetAllAlarmsNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	omci.CommandSequenceNumber = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetAllAlarmsNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextRequest{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Next Request message
func (omci *GetAllAlarmsNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.CommandSequenceNumber)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsNextResponse struct {
	MeBasePacket
	AlarmEntityClass    me.ClassID
	AlarmEntityInstance uint16
	AlarmBitMap         [28]byte // 224 bits
}

func (omci *GetAllAlarmsNextResponse) String() string {
	return fmt.Sprintf("%v, CID: %v, EID: (%d/%#x), Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmEntityClass, omci.AlarmEntityInstance,
		omci.AlarmEntityInstance, omci.AlarmBitMap)
}

// DecodeFromBytes decodes the given bytes of a Get All Alarms Next Response into this layer
func (omci *GetAllAlarmsNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+4+28)
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
	omci.AlarmEntityClass = me.ClassID(binary.BigEndian.Uint16(data[4:6]))
	omci.AlarmEntityInstance = binary.BigEndian.Uint16(data[6:8])

	copy(omci.AlarmBitMap[:], data[8:36])
	return nil
}

func decodeGetAllAlarmsNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextResponse{}
	omci.MsgLayerType = LayerTypeGetAllAlarmsNextResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get All Alarms Next Response message
func (omci *GetAllAlarmsNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(2 + 2 + 28)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:], uint16(omci.AlarmEntityClass))
	binary.BigEndian.PutUint16(bytes[2:], omci.AlarmEntityInstance)
	copy(bytes[4:], omci.AlarmBitMap[:])
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadRequest
type MibUploadRequest struct {
	MeBasePacket
}

func (omci *MibUploadRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Request into this layer
func (omci *MibUploadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support MIB Upload Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	return nil
}

func decodeMibUploadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadRequest{}
	omci.MsgLayerType = LayerTypeMibUploadRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Request message
func (omci *MibUploadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Message-Type")
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadResponse
type MibUploadResponse struct {
	MeBasePacket
	NumberOfCommands uint16
}

func (omci *MibUploadResponse) String() string {
	return fmt.Sprintf("%v, NumberOfCommands: %#v",
		omci.MeBasePacket.String(), omci.NumberOfCommands)
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Response into this layer
func (omci *MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(meDefinition, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support MIB Upload Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.NumberOfCommands = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeMibUploadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadResponse{}
	omci.MsgLayerType = LayerTypeMibUploadResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Response message
func (omci *MibUploadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(entity, me.MibUpload) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.NumberOfCommands)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextRequest struct {
	MeBasePacket
	CommandSequenceNumber uint16
}

func (omci *MibUploadNextRequest) String() string {
	return fmt.Sprintf("%v, SequenceNumberCountOrSize: %v",
		omci.MeBasePacket.String(), omci.CommandSequenceNumber)
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Next Request into this layer
func (omci *MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Get All Alarms
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support MIB Upload Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload Next request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload Next request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	omci.CommandSequenceNumber = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeMibUploadNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextRequest{}
	omci.MsgLayerType = LayerTypeMibUploadNextRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Next Request message
func (omci *MibUploadNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support MIB upload
	if !me.SupportsMsgType(entity, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Next Message-Type")
	}
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.CommandSequenceNumber)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextResponse struct {
	MeBasePacket
	ReportedME me.ManagedEntity
}

func (omci *MibUploadNextResponse) String() string {
	return fmt.Sprintf("%v, ReportedME: [%v]",
		omci.MeBasePacket.String(), omci.ReportedME.String())
}

// DecodeFromBytes decodes the given bytes of a MIB Upload Next Response into this layer
func (omci *MibUploadNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+6)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support MibUploadNext
	if !me.SupportsMsgType(meDefinition, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support MIB Upload Next Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for  MIB Upload Next response: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Upload Next response: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	// Decode reported ME.  If an out-of-range sequence number was sent, this will
	// contain an ME with class ID and entity ID of zero and you should get an
	// error of "managed entity definition not found" returned.
	return omci.ReportedME.DecodeFromBytes(data[4:], p, byte(MibUploadNextResponseType))
}

func decodeMibUploadNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextResponse{}
	omci.MsgLayerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Upload Next Response message
func (omci *MibUploadNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support MIB Upload
	if !me.SupportsMsgType(entity, me.MibUploadNext) {
		return me.NewProcessingError("managed entity does not support the MIB Upload Next Message-Type")
	}
	// TODO: Only Baseline supported at this time
	bytesAvailable := MaxBaselineLength - 8 - 8

	return omci.ReportedME.SerializeTo(b, byte(MibUploadNextResponseType), bytesAvailable, opts)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetRequest
type MibResetRequest struct {
	MeBasePacket
}

func (omci *MibResetRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a MIB Reset Request into this layer
func (omci *MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support MIB reset
	if !me.SupportsMsgType(meDefinition, me.MibReset) {
		return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	}
	// Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		msg := fmt.Sprintf("invalid Entity Class for MIB Reset request: %v",
			omci.EntityClass)
		return me.NewProcessingError(msg)
	}
	if omci.EntityInstance != 0 {
		msg := fmt.Sprintf("invalid Entity Instance for MIB Reset request: %v",
			omci.EntityInstance)
		return me.NewUnknownInstanceError(msg)
	}
	return nil
}

func decodeMibResetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetRequest{}
	omci.MsgLayerType = LayerTypeMibResetRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Reset Request message
func (omci *MibResetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Add class ID and entity ID
	return omci.MeBasePacket.SerializeTo(b)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetResponse
type MibResetResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *MibResetResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// DecodeFromBytes decodes the given bytes of a MIB Reset Response into this layer
func (omci *MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support MIB reset
	if !me.SupportsMsgType(meDefinition, me.MibReset) {
		return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	}
	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != me.OnuDataClassID {
		return me.NewProcessingError("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for MIB Reset Response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	return nil
}

func decodeMibResetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetResponse{}
	omci.MsgLayerType = LayerTypeMibResetResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an MIB Reset Response message
func (omci *MibResetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(entity, me.MibReset) {
		return me.NewProcessingError("managed entity does not support the MIB Reset Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
const AlarmBitmapSize = 224

type AlarmNotificationMsg struct {
	MeBasePacket
	AlarmBitmap         [AlarmBitmapSize / 8]byte
	zeroPadding         [3]byte
	AlarmSequenceNumber byte
}

func (omci *AlarmNotificationMsg) String() string {
	return fmt.Sprintf("%v, Sequence Number: %d, Alarm Bitmap: %v",
		omci.MeBasePacket.String(), omci.AlarmSequenceNumber, omci.AlarmBitmap)
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
		msg := "Managed Entity does not support Alarm notifications"
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
		return false, errors.New("Managed Entity does not support Alarm notifications")
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
		return errors.New("Managed Entity does not support Alarm notifications")
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
		return errors.New("Managed Entity does not support Alarm notifications")
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

	// Look for a non-nil/not empty Alarm Map to determine if this ME supports alarms
	if alarmMap := meDefinition.GetAlarmMap(); isUnsupported || (alarmMap != nil && len(alarmMap) > 0) {
		for index, octet := range data[4 : (AlarmBitmapSize/8)-4] {
			omci.AlarmBitmap[index] = octet
		}
		padOffset := 4 + (AlarmBitmapSize / 8)
		omci.zeroPadding[0] = data[padOffset]
		omci.zeroPadding[1] = data[padOffset+1]
		omci.zeroPadding[2] = data[padOffset+2]

		omci.AlarmSequenceNumber = data[padOffset+3]
		return nil
	}
	return me.NewProcessingError("managed entity does not support alarm notifications")
}

func decodeAlarmNotification(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.MsgLayerType = LayerTypeAlarmNotification
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Alarm Notification message
func (omci *AlarmNotificationMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	//var meDefinition me.IManagedEntityDefinition
	//meDefinition, err = me.LoadManagedEntityDefinition(omci.EntityClass,
	//	me.ParamData{EntityID: omci.EntityInstance})
	//if err != nil {
	//	return err
	//}
	// ME needs to support Alarms
	// TODO: Add attribute to ME to specify that alarm is allowed
	//if !me.SupportsMsgType(meDefinition, me.MibReset) {
	//	return me.NewProcessingError("managed entity does not support MIB Reset Message-Type")
	//}
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
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// AttributeValueChangeMsg
type AttributeValueChangeMsg struct {
	MeBasePacket
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *AttributeValueChangeMsg) String() string {
	return fmt.Sprintf("%v, Mask: %#x, attributes: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.Attributes)
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
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:40], p, byte(AttributeValueChangeType))
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

// SerializeTo provides serialization of an Attribute Value Change Notification message
func (omci *AttributeValueChangeMsg) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)

	// Attribute serialization
	// TODO: Only Baseline supported at this time
	bytesAvailable := MaxBaselineLength - 10 - 8

	err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b,
		byte(AttributeValueChangeType), bytesAvailable, false)
	return err
}

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
		omci.MsgLayerType = LayerTypeTestResult
		return decodingLayerDecoder(omci, data, p)

	case me.AniGClassID, me.ReAniGClassID, me.PhysicalPathTerminationPointReUniClassID,
		me.ReUpstreamAmplifierClassID, me.ReDownstreamAmplifierClassID:
		omci := &OpticalLineSupervisionTestRequest{}
		omci.MsgLayerType = LayerTypeTestResult
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
func (omci *TestRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	if omci.Payload == nil {
		return errors.New("Test Results payload is missing")
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
func (omci *OpticalLineSupervisionTestRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
func (omci *TestResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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

/////////////////////////////////////////////////////////////////////////////
//
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

// DecodeFromBytes decodes the given bytes of a Start Software Download Request into this layer
func (omci *StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+4)
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
	omci.WindowSize = data[4]
	omci.ImageSize = binary.BigEndian.Uint32(data[5:9])
	omci.NumberOfCircuitPacks = data[9]
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks))
	}
	omci.CircuitPacks = make([]uint16, omci.NumberOfCircuitPacks)
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		omci.CircuitPacks[index] = binary.BigEndian.Uint16(data[10+(index*2):])
	}
	return nil
}

func decodeStartSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeStartSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Start Software Download Request message
func (omci *StartSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
		return me.NewProcessingError("managed entity does not support the SStart Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download request")
	}
	if omci.NumberOfCircuitPacks < 1 || omci.NumberOfCircuitPacks > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Circuit Packs: %v, must be 1..9",
			omci.NumberOfCircuitPacks))
	}
	bytes, err := b.AppendBytes(6 + (2 * int(omci.NumberOfCircuitPacks)))
	if err != nil {
		return err
	}
	bytes[0] = omci.WindowSize
	binary.BigEndian.PutUint32(bytes[1:], omci.ImageSize)
	bytes[5] = omci.NumberOfCircuitPacks
	for index := 0; index < int(omci.NumberOfCircuitPacks); index++ {
		binary.BigEndian.PutUint16(bytes[6+(index*2):], omci.CircuitPacks[index])
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
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

// DecodeFromBytes decodes the given bytes of a Start Software Download Response into this layer
func (omci *StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Start Software Download
	if !me.SupportsMsgType(meDefinition, me.StartSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support Start Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Start Software Download response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.WindowSize = data[5]
	omci.NumberOfInstances = data[6]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		omci.MeResults = make([]DownloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[7+(index*3):])
			omci.MeResults[index].Result = me.Results(data[9+(index*3)])
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

// SerializeTo provides serialization of an Start Software Download Response message
func (omci *StartSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(3 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Start Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.WindowSize
	bytes[2] = omci.NumberOfInstances

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Circuit Packs: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[3+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for Start Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[5+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	SectionNumber byte
	SectionData   [31]byte // 0 padding if final transfer requires only a partial block
}

func (omci *DownloadSectionRequest) String() string {
	return fmt.Sprintf("%v, Section #: %v",
		omci.MeBasePacket.String(), omci.SectionNumber)
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
	omci.SectionNumber = data[4]
	copy(omci.SectionData[0:], data[5:])
	return nil
}

func decodeDownloadSectionRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.MsgLayerType = LayerTypeDownloadSectionRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Download Section Request message
func (omci *DownloadSectionRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(1 + len(omci.SectionData))
	if err != nil {
		return err
	}
	bytes[0] = omci.SectionNumber
	copy(bytes[1:], omci.SectionData[0:])
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionResponse struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	Result        me.Results
	SectionNumber byte
}

func (omci *DownloadSectionResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Section #: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.SectionNumber)
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
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.SectionNumber = data[5]
	return nil
}

func decodeDownloadSectionResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.MsgLayerType = LayerTypeDownloadSectionResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Download Section Response message
func (omci *DownloadSectionResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for Download Section response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.SectionNumber
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
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

// DecodeFromBytes decodes the given bytes of an End Software Download Request into this layer
func (omci *EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+7)
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
	omci.CRC32 = binary.BigEndian.Uint32(data[4:8])
	omci.ImageSize = binary.BigEndian.Uint32(data[8:12])
	omci.NumberOfInstances = data[12]

	if omci.NumberOfInstances < 1 || omci.NumberOfInstances > 9 {
		return me.NewProcessingError(fmt.Sprintf("invalid number of Instances: %v, must be 1..9",
			omci.NumberOfInstances))
	}
	omci.ImageInstances = make([]uint16, omci.NumberOfInstances)

	for index := 0; index < int(omci.NumberOfInstances); index++ {
		omci.ImageInstances[index] = binary.BigEndian.Uint16(data[13+(index*2):])
	}
	return nil
}

func decodeEndSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadRequest{}
	omci.MsgLayerType = LayerTypeEndSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an End Software Download Request message
func (omci *EndSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(9 + (2 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(bytes[0:4], omci.CRC32)
	binary.BigEndian.PutUint32(bytes[4:8], omci.ImageSize)
	bytes[8] = omci.NumberOfInstances
	for index := 0; index < int(omci.NumberOfInstances); index++ {
		binary.BigEndian.PutUint16(bytes[9+(index*2):], omci.ImageInstances[index])
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
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

// DecodeFromBytes decodes the given bytes of an End Software Download Response into this layer
func (omci *EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.EndSoftwareDownload) {
		return me.NewProcessingError("managed entity does not support End Software Download Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for End Software Download response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	omci.NumberOfInstances = data[5]

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		omci.MeResults = make([]DownloadResults, omci.NumberOfInstances)

		for index := 0; index < int(omci.NumberOfInstances); index++ {
			omci.MeResults[index].ManagedEntityID = binary.BigEndian.Uint16(data[6+(index*3):])
			omci.MeResults[index].Result = me.Results(data[8+(index*3)])
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

// SerializeTo provides serialization of an End Software Download Response message
func (omci *EndSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(2 + (3 * int(omci.NumberOfInstances)))
	if err != nil {
		return err
	}
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results for End Software Download response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	bytes[1] = omci.NumberOfInstances

	if omci.NumberOfInstances > 9 {
		msg := fmt.Sprintf("invalid number of Instances: %v, must be 0..9",
			omci.NumberOfInstances)
		return errors.New(msg)
	}
	if omci.NumberOfInstances > 0 {
		for index := 0; index < int(omci.NumberOfInstances); index++ {
			binary.BigEndian.PutUint16(bytes[2+(3*index):], omci.MeResults[index].ManagedEntityID)

			if omci.MeResults[index].Result > me.DeviceBusy {
				msg := fmt.Sprintf("invalid results for End Software Download instance %v response: %v, must be 0..6",
					index, omci.MeResults[index])
				return errors.New(msg)
			}
			bytes[4+(3*index)] = byte(omci.MeResults[index].Result)
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct {
	MeBasePacket  // Note: EntityInstance for software download is two specific values
	ActivateFlags byte
}

func (omci *ActivateSoftwareRequest) String() string {
	return fmt.Sprintf("%v, Flags: %#x",
		omci.MeBasePacket.String(), omci.ActivateFlags)
}

// DecodeFromBytes decodes the given bytes of an Activate Software Request into this layer
func (omci *ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software request")
	}
	omci.ActivateFlags = data[4]
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

// SerializeTo provides serialization of an Activate Software message
func (omci *ActivateSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = omci.ActivateFlags
	if omci.ActivateFlags > 2 {
		msg := fmt.Sprintf("invalid results for Activate Software request: %v, must be 0..2",
			omci.ActivateFlags)
		return errors.New(msg)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *ActivateSoftwareResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// DecodeFromBytes decodes the given bytes of an Activate Softwre Response into this layer
func (omci *ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support End Software Download
	if !me.SupportsMsgType(meDefinition, me.ActivateSoftware) {
		return me.NewProcessingError("managed entity does not support Activate Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Activate Software response")
	}
	omci.Result = me.Results(data[4])
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

// SerializeTo provides serialization of an Activate Software Response message
func (omci *ActivateSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Activate Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareRequest struct {
	MeBasePacket
}

func (omci *CommitSoftwareRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Commit Software Request into this layer
func (omci *CommitSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
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

// SerializeTo provides serialization of an Commit Software Request message
func (omci *CommitSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareResponse struct {
	MeBasePacket
	Result me.Results
}

func (omci *CommitSoftwareResponse) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Commit Softwar Response into this layer
func (omci *CommitSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Commit Software
	if !me.SupportsMsgType(meDefinition, me.CommitSoftware) {
		return me.NewProcessingError("managed entity does not support Commit Software Message-Type")
	}
	// Software Image Entity Class are always use the Software Image
	if omci.EntityClass != me.SoftwareImageClassID {
		return me.NewProcessingError("invalid Entity Class for Commit Software response")
	}
	omci.Result = me.Results(data[4])
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

// SerializeTo provides serialization of an Commit Software Response message
func (omci *CommitSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result > me.Results(6) {
		msg := fmt.Sprintf("invalid results for Commit Software response: %v, must be 0..6",
			omci.Result)
		return errors.New(msg)
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeRequest struct {
	MeBasePacket
	Year   uint16
	Month  uint8
	Day    uint8
	Hour   uint8
	Minute uint8
	Second uint8
}

func (omci *SynchronizeTimeRequest) String() string {
	return fmt.Sprintf("%v, Date-Time: %d/%d/%d-%02d:%02d:%02d",
		omci.MeBasePacket.String(), omci.Year, omci.Month, omci.Day, omci.Hour, omci.Minute, omci.Second)
}

// DecodeFromBytes decodes the given bytes of a Synchronize Time Request into this layer
func (omci *SynchronizeTimeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+7)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(meDefinition, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support Synchronize Time Message-Type")
	}
	// Synchronize Time Entity Class are always ONU-G (256) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassID {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time request")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time request")
	}
	omci.Year = binary.BigEndian.Uint16(data[4:6])
	omci.Month = data[6]
	omci.Day = data[7]
	omci.Hour = data[8]
	omci.Minute = data[9]
	omci.Second = data[10]
	return nil
}

func decodeSynchronizeTimeRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeRequest{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Synchronize Time Request message
func (omci *SynchronizeTimeRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(entity, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	bytes, err := b.AppendBytes(7)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.Year)
	bytes[2] = omci.Month
	bytes[3] = omci.Day
	bytes[4] = omci.Hour
	bytes[5] = omci.Minute
	bytes[6] = omci.Second
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeResponse struct {
	MeBasePacket
	Result         me.Results
	SuccessResults uint8 // Only if 'Result' is 0 -> success
}

func (omci *SynchronizeTimeResponse) String() string {
	return fmt.Sprintf("%v, Results: %d (%v), Success: %d",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.SuccessResults)
}

// DecodeFromBytes decodes the given bytes of a Synchronize Time Response into this layer
func (omci *SynchronizeTimeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(meDefinition, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support Synchronize Time Message-Type")
	}
	// Synchronize Time Entity Class are always ONU-G (256) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassID {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time response")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > me.DeviceBusy {
		msg := fmt.Sprintf("invalid results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	omci.SuccessResults = data[5]
	return nil
}

func decodeSynchronizeTimeResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeResponse{}
	omci.MsgLayerType = LayerTypeSynchronizeTimeResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Synchronize Time Response message
func (omci *SynchronizeTimeResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// Synchronize Time Entity Class are always ONU DATA (2) and Entity Instance of 0
	if omci.EntityClass != me.OnuGClassID {
		return me.NewProcessingError("invalid Entity Class for Synchronize Time response")
	}
	if omci.EntityInstance != 0 {
		return me.NewUnknownInstanceError("invalid Entity Instance for Synchronize Time response")
	}
	// ME needs to support Synchronize Time
	if !me.SupportsMsgType(entity, me.SynchronizeTime) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	numBytes := 2
	if omci.Result != me.Success {
		numBytes = 1
	}
	bytes, err := b.AppendBytes(numBytes)
	if err != nil {
		return err
	}
	bytes[0] = uint8(omci.Result)
	if omci.Result == me.Success {
		bytes[1] = omci.SuccessResults
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootRequest struct {
	MeBasePacket
	RebootCondition byte
}

func (omci *RebootRequest) String() string {
	return fmt.Sprintf("%v, Reboot Condition: %v",
		omci.MeBasePacket.String(), omci.RebootCondition)
}

// DecodeFromBytes decodes the given bytes of a Reboot Request into this layer
func (omci *RebootRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Reboot
	if !me.SupportsMsgType(meDefinition, me.Reboot) {
		return me.NewProcessingError("managed entity does not support Reboot Message-Type")
	}
	omci.RebootCondition = data[4]
	if omci.RebootCondition > 3 {
		msg := fmt.Sprintf("invalid reboot condition code: %v, must be 0..3", omci.RebootCondition)
		return errors.New(msg)
	}
	return nil
}

func decodeRebootRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootRequest{}
	omci.MsgLayerType = LayerTypeRebootRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Reboot Request message
func (omci *RebootRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support Reboot
	if !me.SupportsMsgType(entity, me.Reboot) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	if omci.RebootCondition > 3 {
		return me.NewProcessingError(fmt.Sprintf("invalid reboot condition code: %v, must be 0..3",
			omci.RebootCondition))
	}
	bytes[0] = omci.RebootCondition
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootResponse struct {
	MeBasePacket
	Result me.Results
}

// DecodeFromBytes decodes the given bytes of a Reboot Response into this layer
func (omci *RebootResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v)",
		omci.MeBasePacket.String(), omci.Result, omci.Result)
}

// DecodeFromBytes decodes the given bytes of a Reboot Response into this layer
func (omci *RebootResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Reboot
	if !me.SupportsMsgType(meDefinition, me.Reboot) {
		return me.NewProcessingError("managed entity does not support Reboot Message-Type")
	}
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid reboot results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	omci.Result = me.Results(data[4])
	return nil
}

func decodeRebootResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootResponse{}
	omci.MsgLayerType = LayerTypeRebootResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Reboot Response message
func (omci *RebootResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	// ME needs to support Reboot
	if !me.SupportsMsgType(entity, me.Reboot) {
		return me.NewProcessingError("managed entity does not support the Synchronize Time Message-Type")
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid reboot results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	bytes[0] = byte(omci.Result)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextRequest struct {
	MeBasePacket
	AttributeMask  uint16
	SequenceNumber uint16
}

func (omci *GetNextRequest) String() string {
	return fmt.Sprintf("%v, Attribute Mask: %#x, Sequence Number: %v",
		omci.MeBasePacket.String(), omci.AttributeMask, omci.SequenceNumber)
}

// DecodeFromBytes decodes the given bytes of a Get Next Request into this layer
func (omci *GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+4)
	if err != nil {
		return err
	}
	meDefinition, omciErr := me.LoadManagedEntityDefinition(omci.EntityClass,
		me.ParamData{EntityID: omci.EntityInstance})
	if omciErr.StatusCode() != me.Success {
		return omciErr.GetError()
	}
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	// Note: G.988 specifies that an error code of (3) should result if more
	//       than one attribute is requested
	// TODO: Return error.  Have flag to optionally allow it to be encoded
	// TODO: Check that the attribute is a table attirbute.  Issue warning or return error
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	omci.SequenceNumber = binary.BigEndian.Uint16(data[6:8])
	return nil
}

func decodeGetNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextRequest{}
	omci.MsgLayerType = LayerTypeGetNextRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Next Message Type Request
func (omci *GetNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	bytes, err := b.AppendBytes(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, omci.AttributeMask)
	binary.BigEndian.PutUint16(bytes[2:], omci.SequenceNumber)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextResponse struct {
	MeBasePacket
	Result        me.Results
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

// SerializeTo provides serialization of an Get Next Message Type Response
func (omci *GetNextResponse) String() string {
	return fmt.Sprintf("%v, Result: %v, Attribute Mask: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.Result, omci.AttributeMask, omci.Attributes)
}

// DecodeFromBytes decodes the given bytes of a Get Next Response into this layer
func (omci *GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support Get Next Message-Type")
	}
	omci.Result = me.Results(data[4])
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid get next results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[5:7])

	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[7:], p, byte(GetNextResponseType))
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
	panic("All Managed Entities have an EntityID attribute")
}

func decodeGetNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextResponse{}
	omci.MsgLayerType = LayerTypeGetNextResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Next Message Type Response
func (omci *GetNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	if !me.SupportsMsgType(meDefinition, me.GetNext) {
		return me.NewProcessingError("managed entity does not support the Get Next Message-Type")
	}
	bytes, err := b.AppendBytes(3)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	if omci.Result > 6 {
		msg := fmt.Sprintf("invalid get next results code: %v, must be 0..6", omci.Result)
		return errors.New(msg)
	}
	binary.BigEndian.PutUint16(bytes[1:3], omci.AttributeMask)

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
	// Attribute serialization
	switch omci.Result {
	default:
		break

	case me.Success:
		// TODO: Only Baseline supported at this time
		bytesAvailable := MaxBaselineLength - 11 - 8

		err, _ = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b,
			byte(GetNextResponseType), bytesAvailable, false)
		if err != nil {
			return err
		}
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

// DecodeFromBytes decodes the given bytes of a Test Result Notification into this layer
func (omci *TestResultNotification) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4)
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
	omci.Payload = make([]byte, MaxTestResultsLength)
	copy(omci.Payload, omci.MeBasePacket.Payload)
	return nil
}

// SerializeTo provides serialization of an Test Result notification message
func (omci *TestResultNotification) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
		return errors.New("Test Results payload is missing")
	}
	if len(omci.Payload) > MaxTestResultsLength {
		msg := fmt.Sprintf("Invalid Test Results payload size. Received %v bytes, expected %v",
			len(omci.Payload), MaxTestResultsLength)
		return errors.New(msg)
	}
	bytes, err := b.AppendBytes(len(omci.Payload))
	if err != nil {
		return err
	}

	copy(bytes, omci.Payload)
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

func (omci *OpticalLineSupervisionTestResult) TestResults() []byte {
	return omci.MeBasePacket.Payload
}

// DecodeFromBytes decodes the given bytes of a Test Result Notification into this layer
func (omci *OpticalLineSupervisionTestResult) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 4+17)
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
	omci.PowerFeedVoltageType = data[4]
	omci.PowerFeedVoltage = binary.BigEndian.Uint16(data[5:])

	// Type = 3
	omci.ReceivedOpticalPowerType = data[7]
	omci.ReceivedOpticalPower = binary.BigEndian.Uint16(data[8:])

	// Type = 5
	omci.MeanOpticalLaunchType = data[10]
	omci.MeanOpticalLaunch = binary.BigEndian.Uint16(data[11:])

	// Type = 9
	omci.LaserBiasCurrentType = data[13]
	omci.LaserBiasCurrent = binary.BigEndian.Uint16(data[14:])

	// Type = 12
	omci.TemperatureType = data[16]
	omci.Temperature = binary.BigEndian.Uint16(data[17:])

	omci.GeneralPurposeBuffer = binary.BigEndian.Uint16(data[19:])
	return nil
}

// SerializeTo provides serialization of an Test Result notification message
func (omci *OpticalLineSupervisionTestResult) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes, err := b.AppendBytes(17)
	if err != nil {
		return err
	}

	bytes[0] = omci.PowerFeedVoltageType
	binary.BigEndian.PutUint16(bytes[1:], omci.PowerFeedVoltage)
	bytes[3] = omci.ReceivedOpticalPowerType
	binary.BigEndian.PutUint16(bytes[4:], omci.ReceivedOpticalPower)
	bytes[6] = omci.MeanOpticalLaunchType
	binary.BigEndian.PutUint16(bytes[7:], omci.MeanOpticalLaunch)
	bytes[9] = omci.LaserBiasCurrentType
	binary.BigEndian.PutUint16(bytes[10:], omci.LaserBiasCurrent)
	bytes[12] = omci.TemperatureType
	binary.BigEndian.PutUint16(bytes[13:], omci.Temperature)
	binary.BigEndian.PutUint16(bytes[15:], omci.GeneralPurposeBuffer)
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataRequest struct {
	MeBasePacket
	AttributeMask uint16
}

func (omci *GetCurrentDataRequest) String() string {
	return fmt.Sprintf("%v, Attribute Mask: %#x",
		omci.MeBasePacket.String(), omci.AttributeMask)
}

// DecodeFromBytes decodes the given bytes of a Get Current Data Request into this layer
func (omci *GetCurrentDataRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support GetNext
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	// Note: G.988 specifies that an error code of (3) should result if more
	//       than one attribute is requested
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func decodeGetCurrentDataRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataRequest{}
	omci.MsgLayerType = LayerTypeGetCurrentDataRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Get Current Data Request message
func (omci *GetCurrentDataRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataResponse struct {
	MeBasePacket
	Result        me.Results
	AttributeMask uint16
	Attributes    me.AttributeValueMap
}

func (omci *GetCurrentDataResponse) String() string {
	return fmt.Sprintf("%v, Result: %d (%v), Attribute Mask: %#x, Attributes: %v",
		omci.MeBasePacket.String(), omci.Result, omci.Result, omci.AttributeMask, omci.Attributes)
}

// DecodeFromBytes decodes the given bytes of a Get Current Data Respnse into this layer
func (omci *GetCurrentDataResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
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
	// ME needs to support Set
	if !me.SupportsMsgType(meDefinition, me.GetCurrentData) {
		return me.NewProcessingError("managed entity does not support Get Current Data Message-Type")
	}
	omci.AttributeMask = binary.BigEndian.Uint16(data[4:6])

	switch omci.Result {
	case me.ProcessingError, me.NotSupported, me.UnknownEntity, me.UnknownInstance, me.DeviceBusy:
		return nil // Done (do not try and decode attributes)
	}
	// Attribute decode
	omci.Attributes, err = meDefinition.DecodeAttributes(omci.AttributeMask, data[6:], p, byte(GetCurrentDataResponseType))
	if err != nil {
		return err
	}
	return nil
}

func decodeGetCurrentDataResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataResponse{}
	omci.MsgLayerType = LayerTypeGetCurrentDataResponse
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
	bytes, err := b.AppendBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], omci.AttributeMask)

	// Attribute serialization
	// TODO: Only Baseline supported at this time
	bytesAvailable := MaxBaselineLength - 9 - 8
	var failedMask uint16

	err, failedMask = meDefinition.SerializeAttributes(omci.Attributes, omci.AttributeMask, b,
		byte(GetCurrentDataResponseType), bytesAvailable, opts.FixLengths)

	if failedMask != 0 {
		// TODO: See GetResponse serialization above for the steps here
		return me.NewMessageTruncatedError("getCurrentData attribute truncation not yet supported")
	}
	if err != nil {
		return err
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct {
	MeBasePacket
	// TODO: Fix me when extended messages supported)
}

func (omci *SetTableRequest) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Set Table Request into this layer
func (omci *SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 6+2)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

func decodeSetTableRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableRequest{}
	omci.MsgLayerType = LayerTypeSetTableRequest
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Table Message Type Request
func (omci *SetTableRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") /// TODO: Fix me when extended messages supported)
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableResponse struct {
	MeBasePacket
	// TODO: Fix me when extended messages supported)
}

func (omci *SetTableResponse) String() string {
	return fmt.Sprintf("%v", omci.MeBasePacket.String())
}

// DecodeFromBytes decodes the given bytes of a Set Table Response into this layer
func (omci *SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Common ClassID/EntityID decode in msgBase
	err := omci.MeBasePacket.DecodeFromBytes(data, p, 6+1)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

func decodeSetTableResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableResponse{}
	omci.MsgLayerType = LayerTypeSetTableResponse
	return decodingLayerDecoder(omci, data, p)
}

// SerializeTo provides serialization of an Set Table Message Type Response
func (omci *SetTableResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	return errors.New("need to implement") // TODO: Fix me when extended messages supported)
}

/////////////////////////////////////////////////////////////////////////////
//
type UnsupportedMessageTypeResponse struct {
	MeBasePacket
	Result me.Results
}

// DecodeFromBytes decodes the given bytes of an Unsupported Message Type Response into this layer
func (omci *UnsupportedMessageTypeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("you should never really decode this")
}

// SerializeTo provides serialization of an Unsupported Message Type Response
func (omci *UnsupportedMessageTypeResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// Basic (common) OMCI Header is 8 octets, 10
	err := omci.MeBasePacket.SerializeTo(b)
	if err != nil {
		return err
	}
	bytes, err := b.AppendBytes(1)
	if err != nil {
		return err
	}
	bytes[0] = byte(omci.Result)
	return nil
}
