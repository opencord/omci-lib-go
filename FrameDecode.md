# Frame Decode Information

The [omci-lib-go](https://github.com/opencord/omci-lib-go) library provides go-packet
decode and serialization for the 
[ITU G.988 OMCI](https://www.itu.int/rec/T-REC-G.988/recommendation.asp?lang=en&parent=T-REC-G.988-202003-I!Amd3)
specification and currently supports the 3/2020 Amendment 3 of G.988. As both new amendments are issued and
ONU/OLT vendors may implement the standard differently in minor ways, a need to be able to relax the
decode of a received frame was required of the library. Since the go-packet standard does not support this
natively, an OMCI library specific pair of API calls was created to be able to get/set relaxed decoding
of OMCI frames on a message-type basis.

The default/initial setting of the library is to relax decode for received frames for known or
expected issues.

In addition to relaxed decoding, the ability to receive undefined Managed Entity (ITU or vendor specific)
has been part of this library for some time. This document provides information on those capabilities as
they are similar in nature with the need for relaxed decoding.

## GetOmciRelaxedDecode

func GetRelaxedDecode(msgType MsgType, request bool) bool

This function can be used to query the state of relaxed decode for a specific OMCI direction type and
direction (request/response). If relax decoding is not supported by the requested message type, false
is returned.

For Notifications, set 'request' to **false**.


## SetOmciRelaxedDecode

func SetRelaxedDecode(msgType MsgType, request bool, relax bool) error 

This function can be used to enable/disable relaxed decode for a specific OMCI direction type and
direction (request/resposne). An error is returned if relax decoding is not supported for the
requested type.

For Notifications, set 'request' to **false**.

## Expected Deviations

This section details expected deviations from the standard that requires relaxed decode
capability.

### New Attribute Definitions

As new revisions of G.988 are produced, existing Managed Entity definitions may have new
attributes defined.

### New/Unknown G.988 Managed Entity Definitions

TODO: This section needs to be documented. This capability has been part of this library
for some time.

### Vendor Specific Managed Entity Definitions

TODO: This section needs to be documented. This capability has been part of this library
for some time.
## Known Vendor Deviations

This section documents known deviations of the G.988 standard that have been identified
and can be compensated for by the OMCI library.

### Get Response

For the baseline message set, a Get Response reserves the last 4 octets of the frame for
attribute error information. This space is always reserved even when the result of the
response is zero (success). At least one vendor (or ONU library) makes use of this space
for normal attribute storage when a success result is returned.