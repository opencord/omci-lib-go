# OMCI

OMCI gopacket library supports the encoding and decoding of ITU G.988 OMCI
messages. Support for the Baseline and Extended Message Set has been completed for
basic serialization and decode and some support for the MEFrame library.

Future work is to focus on getting unit test coverage >= 75% for the basic serialization
and decode objects before work for additional extended message set support in the
MEFrame library.

# Recent Changes
In v2.1.0, a pair of library calls were added to help support relaxed decoding of OMCI
frames. The primary intent is to allow for reception of frames that may have been
encoded with either a newer release of the G.988 OMCI specification or with a few minor
ONU/OLT implementation errors that are minor and by allowing them greater interoperability
can be achieved. To track this change and document the API calls, the 
[FrameDecode](https://github.com/opencord/omci-lib-go/blob/master/FrameDecode.md) document
provides further information on this new capability.

## v2.0.0
In v2.0.0, the directory/package structure was reorganized (no API changes otherwise)
in order to separate message type functionality on a filename basis. This will allow
for future features and bug fixes to be better localized and to allow for better
unit test coverage reporting.

Bug fixes will typically result in an increment of the third number in the version string
and additional feature support will typically result in incrementing the second number. 
 
## Current user-test coverage

The _**make** test_ command can be used to create code coverage support for the
library.  The current coverage for version 2.0.0 (as of 9/08/2021) is:

Entire Project:         97.3% of files and 70.2% of statements
Generated Subdirectory: 98.1% of files and 50.1% of statements
meframe Subdirectory:   80% of files and 55.4% of statements

Main Message Directory (below):

| File              | Coverage | < 75% |
| ----------------: | :------: | :---: |
| alarms.go         |  74.3%   |   Y   |
| avc.go            |  86%     |       |
| create.go         |  82.5%   |       |
| delete.go         |  85.5%   |       |
| get.go            |  78.4%   |       |
| getcurrent.go     |  69.4%   |       |
| getnext.go        |  79.3%   |       |
| layers.go         |  100%    |       |
| mebase.go         |  93.3%   |       |
| messagetypes.go   |  100%    |       |
| mibreset.go       |  76.6%   |       |
| mibupload.go      |  78.9%   |       |
| omci.go           |  90.6%   |       |
| reboot.go         |  81.2%   |       |
| relaxed_decode.go |  78.3%   |       |
| set.go            |  77.3%   |       |
| settable.go       |  81.5%   |       |
| software.go       |  75.2%   |       |
| synctime.go       |  79.3%   |       |
| test.go           |  79.9%   |       |

## Other outstanding items

A few additional features have been requested and are listed below for future inclusion
in the package:

 - Constraint checking (these are not yet fully parsed/provided by the OMCI code generated
   structs). This feature will hopefully be available in the near future.
 - Add AVC flag for appropriate attributes
 - Review other gopacket libraries for logging support and add some type of logging support
   if it is standard. If not, recommend design patterns users of this library can use to detect
   issues in decode or serialization.
 - For several of the software image message types, multiple instances can be supported. Unit
   test and source implementation to verify correct implementation is needed.
 
Also searching through the code for _TODO_ statements will also yield additional areas of
work to be performed.

## What is not provided by this library

This library is not a full OMCI stack for either an OLT or an ONU. It is focused primarily on
packet decode/serialization and a variety of structs and functions that are useful for handling
the creation of OMCI frames and handling decoded frames from the PON.

### OLT
For an OLT-side OMCI stack, you would still need to write:
 - OMCI CC sender & receiver (stop & wait protocol) with appropriate timeout support
 - OLT State machines to support 
   - MIB Uploads/Audits/Resynchronization (and a MIB database implemention),
   - More sophisticated get & get-next support to make handle of MEs with
     lots of attributes or table attributes easy to handle and code,
   - Alarm Table support,
   - OMCI ME/Msg-Type capabilities inquiry,
   - Performance Monitoring collection (and initial time synchronization), 
   - Service implementation

### ONU
For an ONU-side OMCI stack, you would still need to write:
   - OMCC implementation,
   - MIB Database,
   - Get-Next cache for table attributes,
   - MIB upload next cache for MIB uploads,
   - Generation of any alarms/AVC notifications,
   - Actually acting on the create/delete/get/set/... requests from an OLT

### Vendor specific error information
Rule 5 of section A.1.1 of the G.988 standard provides for the capability of adding
vendor specific error information in the trailing octets of an OMCI response that has
a non-zero (success) error code. The current library does not provide an easy mechanism
for encoding or easy decoding of additional error information at this time.
