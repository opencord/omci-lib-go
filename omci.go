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

// Package omci provides a library of routines to create, manipulate, serialize, and
// decode ITU-T G.988 OMCI messages/packets
package omci

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aead/cmac/aes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	me "github.com/opencord/omci-lib-go/v2/generated"
)

// DeviceIdent identifies the OMCI message format. Currently either baseline or extended.
type DeviceIdent byte

// LayerTypeOMCI provides a gopacket LayerType for OMCI messages
var (
	LayerTypeOMCI gopacket.LayerType
)

func init() {
	LayerTypeOMCI = gopacket.RegisterLayerType(1000,
		gopacket.LayerTypeMetadata{
			Name:    "OMCI",
			Decoder: gopacket.DecodeFunc(decodeOMCI),
		})
}

const (
	// Device Identifiers
	_ = iota
	// BaselineIdent message are composed of a fixed 40 octet packet + 8-octet trailer. All
	// G-PON OLTs and ONUs support the baseline message set
	BaselineIdent DeviceIdent = 0x0A

	// ExtendedIdent messages are up to 1920 octets but may not be supported by all ONUs or OLTs.
	ExtendedIdent DeviceIdent = 0x0B
)

var omciIK = []byte{0x18, 0x4b, 0x8a, 0xd4, 0xd1, 0xac, 0x4a, 0xf4,
	0xdd, 0x4b, 0x33, 0x9e, 0xcc, 0x0d, 0x33, 0x70}

func (di DeviceIdent) String() string {
	switch di {
	default:
		return "Unknown"

	case BaselineIdent:
		return "Baseline"

	case ExtendedIdent:
		return "Extended"
	}
}

// MaxBaselineLength is the maximum number of octets allowed in an OMCI Baseline
// message.  Depending on the adapter, it may or may not include the
const MaxBaselineLength = 48

// MaxExtendedLength is the maximum number of octets allowed in an OMCI Extended
// message (including header).
const MaxExtendedLength = 1980

// MaxAttributeMibUploadNextBaselineLength is the maximum payload size for attributes for
// a Baseline MIB Upload Next message.29
const MaxAttributeMibUploadNextBaselineLength = MaxBaselineLength - 14 - 8

// MaxAttributeGetNextBaselineLength is the maximum payload size for attributes for
// a Baseline MIB Get Next message for the baseline message set. This is just the
// attribute portion of the message contents and does not include the Result Code & Attribute Mask.
const MaxAttributeGetNextBaselineLength = MaxBaselineLength - 11 - 8

// MaxDownloadSectionLength is the maximum payload size for section data of
// a Download Section request message for the baseline message set.
const MaxDownloadSectionLength = 31

// MaxTestRequestLength is the maximum payload size for test request message
// for the baseline message set.
const MaxTestRequestLength = MaxBaselineLength - 8 - 8

// MaxTestResultsLength is the maximum payload size for test results message
// for the baseline message set.
const MaxTestResultsLength = MaxBaselineLength - 8 - 8

// MaxManagedEntityMibUploadNextExtendedLength is the maximum payload size for ME
// entries for an Extended MIB Upload Next message. Extended messages differ from
// the baseline as multiple MEs can be reported in a single frame, just not multiple
// attributes.
const MaxManagedEntityMibUploadNextExtendedLength = MaxExtendedLength - 10 - 4

// MaxAttributeGetNextExtendedLength is the maximum payload size for attributes for
// a Extended MIB Get Next message. This is just the attribute portion of the
// message contents and does not include the Result Code & Attribute Mask.
const MaxAttributeGetNextExtendedLength = MaxExtendedLength - 13 - 4

// MaxDownloadSectionExtendedLength is the maximum payload size for section data of
// a Download Section request message for the extended message set.
const MaxDownloadSectionExtendedLength = MaxExtendedLength - 11 - 4

// NullEntityID is often used as the Null/void Managed Entity ID for attributes
// that are used to refer to other Managed Entities but are currently not provisioned.
const NullEntityID = uint16(0xffff)

// OMCI defines the common protocol. Extended will be added once
// I can get basic working (and layered properly).  See ITU-T G.988 11/2017 section
// A.3 for more information
type OMCI struct {
	layers.BaseLayer
	TransactionID    uint16
	MessageType      MessageType
	DeviceIdentifier DeviceIdent
	ResponseExpected bool   // Significant for Download Section Request only
	Payload          []byte // TODO: Deprecated.  Use layers.BaseLayer.Payload
	Length           uint16
	MIC              uint32
}

func (omci *OMCI) String() string {
	return fmt.Sprintf("Type: %v, TID: %d (%#x), Ident: %v",
		omci.MessageType, omci.TransactionID, omci.TransactionID, omci.DeviceIdentifier)
}

// LayerType returns LayerTypeOMCI
func (omci *OMCI) LayerType() gopacket.LayerType {
	return LayerTypeOMCI
}

// CanDecode returns the layers that this class can decode
func (omci *OMCI) CanDecode() gopacket.LayerClass {
	return LayerTypeOMCI
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (omci *OMCI) NextLayerType() gopacket.LayerType {
	if next, ok := nextLayerMapping[omci.MessageType]; ok {
		return next
	}
	return gopacket.LayerTypePayload
}

// LayerContents returns the OMCI specific layer information
func (omci *OMCI) LayerContents() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, omci.TransactionID)
	b[2] = byte(omci.MessageType)
	b[3] = byte(omci.DeviceIdentifier)
	return b
}

func decodeOMCI(data []byte, p gopacket.PacketBuilder) error {
	// Allow baseline messages without Length & MIC, but no less
	if len(data) < 4 {
		p.SetTruncated()
		return errors.New("frame header too small")
	}
	omci := &OMCI{}

	switch DeviceIdent(data[3]) {
	default:
		return errors.New("unsupported message set/device identifier")

	case BaselineIdent:
		if len(data) < MaxBaselineLength-8 {
			p.SetTruncated()
			return fmt.Errorf("frame too small. OMCI baseline frame length %v, %v required",
				len(data), MaxBaselineLength-8)
		}
		return omci.DecodeFromBytes(data, p)

	case ExtendedIdent:
		if len(data) < 10 {
			p.SetTruncated()
			return fmt.Errorf("frame too small. OMCI minimal extended frame length %v, 10 required",
				len(data))
		}
		return omci.DecodeFromBytes(data, p)
	}
}

func calculateMicAes128(data []byte) (uint32, error) {
	// See if upstream or downstream
	var downstreamCDir = [...]byte{0x01}
	var upstreamCDir = [...]byte{0x02}

	tid := binary.BigEndian.Uint16(data[0:2])
	var sum []byte
	var err error

	if (data[2]&me.AK) == me.AK || tid == 0 {
		sum, err = aes.Sum(append(upstreamCDir[:], data[:44]...), omciIK, 4)
	} else {
		sum, err = aes.Sum(append(downstreamCDir[:], data[:44]...), omciIK, 4)
	}
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(sum), nil
}

/////////////////////////////////////////////////////////////////////////////
//   Baseline Message encode / decode

// DecodeFromBytes will decode the OMCI layer of a packet/message
func (omci *OMCI) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	// Minimal Baseline and Extended message set length has already been checked
	omci.TransactionID = binary.BigEndian.Uint16(data[0:])
	omci.MessageType = MessageType(data[2])
	omci.DeviceIdentifier = DeviceIdent(data[3])
	omci.ResponseExpected = byte(omci.MessageType)&me.AR == me.AR

	isNotification := (int(omci.MessageType) & ^me.MsgTypeMask) == 0
	if omci.TransactionID == 0 && !isNotification {
		return errors.New("omci Transaction ID is zero for non-Notification type message")
	}
	// Decode length
	var payloadOffset int
	var micOffset int
	var eomOffset int
	if omci.DeviceIdentifier == BaselineIdent {
		omci.Length = MaxBaselineLength - 8
		payloadOffset = 8
		micOffset = MaxBaselineLength - 4
		eomOffset = MaxBaselineLength - 8

		if len(data) >= micOffset {
			length := binary.BigEndian.Uint32(data[micOffset-4:])
			if uint16(length) != omci.Length {
				return me.NewProcessingError("invalid baseline message length")
			}
		}
	} else {
		payloadOffset = 10
		omci.Length = binary.BigEndian.Uint16(data[8:10])
		micOffset = int(omci.Length) + payloadOffset
		eomOffset = micOffset

		if omci.Length > uint16(MaxExtendedLength-payloadOffset) {
			return me.NewProcessingError("extended frame exceeds maximum allowed")
		}
		if len(data) < micOffset {
			p.SetTruncated()
			return me.NewProcessingError("extended frame too small")
		}
	}
	// Extract MIC if present in the data
	if len(data) >= micOffset+4 {
		omci.MIC = binary.BigEndian.Uint32(data[micOffset:])
		actual, _ := calculateMicAes128(data[:micOffset])
		if omci.MIC != actual {
			_ = fmt.Sprintf("invalid MIC, expected %#x, got %#x",
				omci.MIC, actual)
			//return errors.New(msg)
		}
	}
	omci.BaseLayer = layers.BaseLayer{
		Contents: data[:4],
		Payload:  data[4:eomOffset],
	}
	p.AddLayer(omci)
	nextLayer, err := MsgTypeToNextLayer(omci.MessageType, omci.DeviceIdentifier == ExtendedIdent)
	if err != nil {
		return err
	}
	return p.NextDecoder(nextLayer)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (omci *OMCI) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	// OMCI layer error checks
	// Self-initiated Test Results have a TID of 0, OLT-requested do not.
	isNotification := omci.MessageType == AlarmNotificationType ||
		omci.MessageType == AttributeValueChangeType

	if omci.TransactionID == 0 && !isNotification && omci.MessageType != TestResultType {
		return errors.New("omci Transaction ID is zero for non-Notification type message")
	}
	if omci.TransactionID != 0 && isNotification {
		return errors.New("omci Transaction ID is not zero for Notification type message")
	}
	if omci.DeviceIdentifier == 0 {
		omci.DeviceIdentifier = BaselineIdent // Allow uninitialized device identifier
	}
	if omci.DeviceIdentifier == BaselineIdent {
		if omci.Length == 0 {
			omci.Length = MaxBaselineLength - 8 // Allow uninitialized length
		} else if omci.Length != MaxBaselineLength-8 {
			msg := fmt.Sprintf("invalid Baseline message length: %v", omci.Length)
			return errors.New(msg)
		}
	} else if omci.DeviceIdentifier == ExtendedIdent {
		omci.Length = uint16(len(b.Bytes()) - 10)

		// Is length larger than maximum packet (less header and trailing MIC)
		if omci.Length > MaxExtendedLength-10-4 {
			msg := fmt.Sprintf("invalid Extended message length: %v", omci.Length)
			return errors.New(msg)
		}
	} else {
		msg := fmt.Sprintf("invalid device identifier: %#x, Baseline or Extended expected",
			omci.DeviceIdentifier)
		return errors.New(msg)
	}
	binary.BigEndian.PutUint16(bytes, omci.TransactionID)
	// Download section request can optionally have the AR bit set or cleared.  If user passes in this
	// message type and sets download requested, fix up the message type for them.
	if omci.MessageType == DownloadSectionRequestType && omci.ResponseExpected {
		bytes[2] = byte(DownloadSectionRequestWithResponseType)
	} else {
		bytes[2] = byte(omci.MessageType)
	}
	bytes[3] = byte(omci.DeviceIdentifier)
	b.PushLayer(LayerTypeOMCI)

	if omci.DeviceIdentifier == BaselineIdent {
		bufLen := len(b.Bytes())
		padSize := int(omci.Length) - bufLen + 4
		if padSize < 0 {
			msg := fmt.Sprintf("invalid OMCI Message Type length, exceeded allowed frame size by %d bytes",
				-padSize)
			return errors.New(msg)
		}
		padding, err := b.AppendBytes(padSize)
		if err != nil {
			return err
		}
		copy(padding, lotsOfZeros[:])

		// For baseline, always provide the length
		binary.BigEndian.PutUint32(b.Bytes()[MaxBaselineLength-8:], 40)
	}
	if opts.ComputeChecksums {
		micBytes, err := b.AppendBytes(4)
		if err != nil {
			return err
		}
		omci.MIC, _ = calculateMicAes128(bytes[:MaxBaselineLength-4])
		binary.BigEndian.PutUint32(micBytes, omci.MIC)
	}
	return nil
}

// hacky way to zero out memory... there must be a better way?
var lotsOfZeros [MaxExtendedLength]byte // Extended OMCI messages may be up to 1980 bytes long, including headers
