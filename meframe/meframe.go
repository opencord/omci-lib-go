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

package meframe

import (
	"errors"
	"fmt"
	"github.com/deckarep/golang-set"
	"github.com/google/gopacket"
	. "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

var encoderMap map[MessageType]func(*me.ManagedEntity, options) (gopacket.SerializableLayer, error)

func init() {
	encoderMap = make(map[MessageType]func(*me.ManagedEntity, options) (gopacket.SerializableLayer, error))

	encoderMap[CreateRequestType] = CreateRequestFrame
	encoderMap[DeleteRequestType] = DeleteRequestFrame
	encoderMap[SetRequestType] = SetRequestFrame
	encoderMap[GetRequestType] = GetRequestFrame
	encoderMap[GetAllAlarmsRequestType] = GetAllAlarmsRequestFrame
	encoderMap[GetAllAlarmsNextRequestType] = GetAllAlarmsNextRequestFrame
	encoderMap[MibUploadRequestType] = MibUploadRequestFrame
	encoderMap[MibUploadNextRequestType] = MibUploadNextRequestFrame
	encoderMap[MibResetRequestType] = MibResetRequestFrame
	//encoderMap[TestRequestType] = TestRequestFrame
	encoderMap[StartSoftwareDownloadRequestType] = StartSoftwareDownloadRequestFrame
	encoderMap[DownloadSectionRequestType] = DownloadSectionRequestFrame
	encoderMap[EndSoftwareDownloadRequestType] = EndSoftwareDownloadRequestFrame
	encoderMap[ActivateSoftwareRequestType] = ActivateSoftwareRequestFrame
	encoderMap[CommitSoftwareRequestType] = CommitSoftwareRequestFrame
	encoderMap[SynchronizeTimeRequestType] = SynchronizeTimeRequestFrame
	encoderMap[RebootRequestType] = RebootRequestFrame
	encoderMap[GetNextRequestType] = GetNextRequestFrame
	encoderMap[GetCurrentDataRequestType] = GetCurrentDataRequestFrame
	encoderMap[SetTableRequestType] = SetTableRequestFrame
	encoderMap[CreateResponseType] = CreateResponseFrame
	encoderMap[DeleteResponseType] = DeleteResponseFrame
	encoderMap[SetResponseType] = SetResponseFrame
	encoderMap[GetResponseType] = GetResponseFrame
	encoderMap[GetAllAlarmsResponseType] = GetAllAlarmsResponseFrame
	encoderMap[GetAllAlarmsNextResponseType] = GetAllAlarmsNextResponseFrame
	encoderMap[MibUploadResponseType] = MibUploadResponseFrame
	encoderMap[MibUploadNextResponseType] = MibUploadNextResponseFrame
	encoderMap[MibResetResponseType] = MibResetResponseFrame
	//encoderMap[TestResponseType] = TestResponseFrame
	encoderMap[StartSoftwareDownloadResponseType] = StartSoftwareDownloadResponseFrame
	encoderMap[DownloadSectionResponseType] = DownloadSectionResponseFrame
	encoderMap[EndSoftwareDownloadResponseType] = EndSoftwareDownloadResponseFrame
	encoderMap[ActivateSoftwareResponseType] = ActivateSoftwareResponseFrame
	encoderMap[CommitSoftwareResponseType] = CommitSoftwareResponseFrame
	encoderMap[SynchronizeTimeResponseType] = SynchronizeTimeResponseFrame
	encoderMap[RebootResponseType] = RebootResponseFrame
	encoderMap[GetNextResponseType] = GetNextResponseFrame
	encoderMap[GetCurrentDataResponseType] = GetCurrentDataResponseFrame
	encoderMap[SetTableResponseType] = SetTableResponseFrame
	encoderMap[AlarmNotificationType] = AlarmNotificationFrame
	encoderMap[AttributeValueChangeType] = AttributeValueChangeFrame
	//encoderMap[TestResultType] = TestResultFrame
}

type options struct {
	frameFormat               DeviceIdent
	failIfTruncated           bool
	attributeMask             uint16
	result                    me.Results      // Common for many responses
	attrExecutionMask         uint16          // Create Response Only if results == 3 or Set Response only if results == 0
	unsupportedMask           uint16          // Set Response only if results == 9
	sequenceNumberCountOrSize uint16          // For get-next request frames and for frames that return number of commands or length
	transactionID             uint16          // OMCI TID
	mode                      uint8           // Get All Alarms retrieval mode
	alarm                     AlarmOptions    // Alarm related frames
	software                  SoftwareOptions // Software image related frames
	payload                   interface{}     // ME or list of MEs, alarm bitmap, timestamp, ...
	addDefaults               bool            // Add missing SetByCreate attributes for Create Requests
}

var defaultFrameOptions = options{
	frameFormat:               BaselineIdent,
	failIfTruncated:           false,
	attributeMask:             0xFFFF,
	result:                    me.Success,
	attrExecutionMask:         0,
	unsupportedMask:           0,
	sequenceNumberCountOrSize: 0,
	transactionID:             0,
	mode:                      0,
	software:                  defaultSoftwareOptions,
	alarm:                     defaultAlarmOptions,
	payload:                   nil,
	addDefaults:               false,
}

// FrameOption sets options such as frame format, etc.
type FrameOption func(*options)

// FrameFormat determines determines the OMCI message format used on the fiber.
// The default value is BaselineIdent
func FrameFormat(ff DeviceIdent) FrameOption {
	return func(o *options) {
		o.frameFormat = ff
	}
}

// FailIfTruncated determines whether a request to encode a frame that does
// not have enough room for all requested options should fail and return an
// error.
//
// If set to 'false', the behaviour depends on the message type/operation
// requested. The table below provides more information:
//
//   Request Type	Behavour
//	 ------------------------------------------------------------------------
//	 CreateRequest  A single CreateRequest struct is always returned as the
//                  CreateRequest message does not have an attributes Mask
//                  field and a Baseline OMCI message is large enough to
//                  support all Set-By-Create attributes.
//
//   GetResponse	If multiple OMCI response frames are needed to return
//					all requested attributes, only the attributes that can
//					fit will be returned and the FailedAttributeMask field
//					set to the attributes that could not be returned
//
//					If this is an ME with an attribute that is a table, the
//					first GetResponse struct will return the size of the
//					attribute and the following GetNextResponse structs will
//					contain the attribute data. The ONU application is
//					responsible for stashing these extra struct(s) away in
//					anticipation of possible GetNext Requests occurring for
//					the attribute.  See the discussion on Table attributes
//					in the GetResponse section of ITU G.988 for more
//					information.
//
// If set to 'true', no struct(s) are returned and an error is provided.
//
// The default value is 'false'
func FailIfTruncated(f bool) FrameOption {
	return func(o *options) {
		o.failIfTruncated = f
	}
}

// attributeMask determines the attributes to encode into the frame.
// The default value is 0xFFFF which specifies all available attributes
// in the frame
func AttributeMask(m uint16) FrameOption {
	return func(o *options) {
		o.attributeMask = m
	}
}

// AttributeExecutionMask is used by the Create and Set Response frames to indicate
// attributes that failed to be created/set.
func AttributeExecutionMask(m uint16) FrameOption {
	return func(o *options) {
		o.attrExecutionMask = m
	}
}

// UnsupportedAttributeMask is used by the Set Response frames to indicate
// attributes are not supported on this ONU
func UnsupportedAttributeMask(m uint16) FrameOption {
	return func(o *options) {
		o.unsupportedMask = m
	}
}

// Result is used to set returned results in responses
// that have that field
func Result(r me.Results) FrameOption {
	return func(o *options) {
		o.result = r
	}
}

// SequenceNumberCountOrSize is used by the GetNext and MibUploadGetNext request frames and for
// frames that return number of commands or length such as Get (table attribute) or
// MibUpload/GetAllAlarms/...
func SequenceNumberCountOrSize(m uint16) FrameOption {
	return func(o *options) {
		o.sequenceNumberCountOrSize = m
	}
}

// TransactionID is to specify the TID in the OMCI header. The default is
// zero which requires the caller to set it to the appropriate value if this
// is not an autonomous ONU notification frame
func TransactionID(tid uint16) FrameOption {
	return func(o *options) {
		o.transactionID = tid
	}
}

// RetrievalMode is to specify the the Alarm Retrieval Mode in a GetAllAlarms Request
func RetrievalMode(m uint8) FrameOption {
	return func(o *options) {
		o.mode = m
	}
}

// SuccessResult is to specify the the SuccessResult for a SynchronizeTime Response
func SuccessResult(m uint8) FrameOption {
	return func(o *options) {
		o.mode = m
	}
}

// RebootCondition is to specify the the Reboot Condition for a ONU Reboot request
func RebootCondition(m uint8) FrameOption {
	return func(o *options) {
		o.mode = m
	}
}

// Alarm is used to specify a collection of options related to Alarm notifications
func Alarm(ao AlarmOptions) FrameOption {
	return func(o *options) {
		o.alarm = ao
	}
}

// Software is used to specify a collection of options related to Software image
// manipulation
func Software(so SoftwareOptions) FrameOption {
	return func(o *options) {
		o.software = so
	}
}

// Payload is used to specify ME payload options that are not simple types. This
// include the ME (list of MEs) to encode into a GetNextMibUpload response, the
// alarm bitmap for alarm relates responses/notifications, alarm bitmaps, and
// for specifying the download section data when performing Software Download.
func Payload(p interface{}) FrameOption {
	return func(o *options) {
		o.payload = p
	}
}

// AddDefaults is used to specify that if a SetByCreate attribute is not
// specified in the list of attributes for a Create Request, use the attribute
// defined default
func AddDefaults(add bool) FrameOption {
	return func(o *options) {
		o.addDefaults = add
	}
}

// Alarm related frames have a wide variety of settable values. Placing them
// in a separate struct is mainly to keep the base options simple
type AlarmOptions struct {
	AlarmClassID  me.ClassID
	AlarmInstance uint16
	AlarmBitmap   []byte // Should be up to 58 octets
}

var defaultAlarmOptions = AlarmOptions{
	AlarmClassID:  0,
	AlarmInstance: 0,
	AlarmBitmap:   nil,
}

// Software related frames have a wide variety of settable values. Placing them
// in a separate struct is mainly to keep the base options simple
type SoftwareOptions struct {
	WindowSize    uint8 // Window size - 1
	SectionNumber uint8 // [0..Window size - 1]
	ImageSize     uint32
	CircuitPacks  []uint16 // slot (upper 8 bits) and instance (lower 8 bits)
	Results       []DownloadResults
	Data          []byte
}

var defaultSoftwareOptions = SoftwareOptions{
	WindowSize:    0,
	SectionNumber: 0,
	ImageSize:     0,
	CircuitPacks:  nil,
	Results:       nil,
	Data:          nil,
}

// EncodeFrame will encode the Managed Entity specific protocol struct and an
// OMCILayer struct. This struct can be provided to the gopacket.SerializeLayers()
// function to be serialized into a buffer for transmission.
func EncodeFrame(m *me.ManagedEntity, messageType MessageType, opt ...FrameOption) (*OMCI, gopacket.SerializableLayer, error) {
	// Check for message type support
	msgType := me.MsgType(messageType & me.MsgTypeMask)
	meDefinition := m.GetManagedEntityDefinition()

	if !me.SupportsMsgType(meDefinition, msgType) {
		msg := fmt.Sprintf("managed entity %v does not support %v Message-Type",
			meDefinition.GetName(), msgType)
		return nil, nil, errors.New(msg)
	}
	// Decode options
	opts := defaultFrameOptions
	for _, o := range opt {
		o(&opts)
	}
	// TODO: If AttributesMask option passed in, check for deprecated options. Allow encoding option
	//       that will ignore deprecated option.   Add additional in the get and set meframe_test,go
	//       test functions to test this. Also have it test attribute name(s) to see if the attribute
	//       is deprecated.  The OMCI-Parser now supports detection of deprecated attributes and
	//       provides that to the code-generator (and currently available in generated golang code).
	// Note: Transaction ID should be set before frame serialization
	omci := &OMCI{
		TransactionID:    opts.transactionID,
		MessageType:      messageType,
		DeviceIdentifier: opts.frameFormat,
	}
	var meInfo gopacket.SerializableLayer
	var err error

	if encoder, ok := encoderMap[messageType]; ok {
		meInfo, err = encoder(m, opts)
	} else {
		err = fmt.Errorf("message-type: %v/%#x is not supported", messageType, messageType)
	}
	if err != nil {
		return nil, nil, err
	}
	return omci, meInfo, err
}

// For most all create methods below, error checking for valid masks, attribute
// values, and other fields is left to when the frame is actually serialized.

func checkAttributeMask(m *me.ManagedEntity, mask uint16) (uint16, error) {
	if mask == defaultFrameOptions.attributeMask {
		// Scale back to just what is allowed
		return m.GetAllowedAttributeMask(), nil
	}
	if mask&m.GetManagedEntityDefinition().GetAllowedAttributeMask() != mask {
		return 0, errors.New("invalid attribute mask")
	}
	return mask & m.GetManagedEntityDefinition().GetAllowedAttributeMask(), nil
}

// return the maximum space that can be used by attributes
func maxPacketAvailable(m *me.ManagedEntity, opt options) uint {
	if opt.frameFormat == BaselineIdent {
		// OMCI Header          - 4 octets
		// Class ID/Instance ID - 4 octets
		// Length field			- 4 octets
		// MIC                  - 4 octets
		return MaxBaselineLength - 16
	}
	// OMCI Header          - 4 octets
	// Class ID/Instance ID - 4 octets
	// Length field			- 2 octets
	// MIC                  - 4 octets
	return MaxExtendedLength - 14
}

func calculateAttributeMask(m *me.ManagedEntity, requestedMask uint16) (uint16, error) {
	attrDefs := m.GetAttributeDefinitions()
	var entityIDName string
	if entry, ok := attrDefs[0]; ok {
		entityIDName = entry.GetName()
	} else {
		panic("unexpected error") // All attribute definition maps have an entity ID
	}
	attributeNames := make([]interface{}, 0)
	for attrName := range m.GetAttributeValueMap() {
		if attrName == entityIDName {
			continue // No mask for EntityID
		}
		attributeNames = append(attributeNames, attrName)
	}
	calculatedMask, err := me.GetAttributesBitmap(attrDefs, mapset.NewSetWith(attributeNames...))

	if err != nil {
		return 0, err
	}
	return calculatedMask & requestedMask, nil
}

// GenFrame is a helper function to make tests a little easier to read.
// For a real application, use the .../omci/generated/class.go 'New'
// functions to create your Managed Entity and then use it to call the
// EncodeFrame method.
func GenFrame(meInstance *me.ManagedEntity, messageType MessageType, options ...FrameOption) ([]byte, error) {
	omciLayer, msgLayer, err := EncodeFrame(meInstance, messageType, options...)
	if err != nil {
		return nil, err
	}
	// Serialize the frame and send it
	var serializeOptions gopacket.SerializeOptions
	serializeOptions.FixLengths = true

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, serializeOptions, omciLayer, msgLayer)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
