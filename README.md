# OMCI

OMCI gopacket library supports the encoding and decoding of ITU G.988 OMCI
messages.

## Message Types supported and under unit test
The following OMCI message types currently have been coded and are covered
satisfactory by unit tests.

 - CreateRequest
 - CreateResponse
 - DeleteRequest
 - DeleteResponse
 - SetRequest
 - GetRequest
 - GetAllAlarmsRequest
 - GetAllAlarmsResponse
 - GetAllAlarmsNextRequest
 - MibUploadRequest
 - MibUploadResponse
 - MibUploadNextRequest
 - MibResetRequest
 - MibResetResponse
 - SynchronizeTimeRequest

## Message Types supported but lacking full unit test
The following OMCI message types currently have been coded and are partially covered
by unit tests, but work still remains for sufficient/better unit test coverage.

 - SetResponse
 - GetResponse
 - GetAllAlarmsNextResponse
 - MibUploadNextResponse
 - SynchronizeTimeResponse
 - AttributeValueChange
 - RebootRequest
 - RebootResponse
 - StartSoftwareDownloadRequest
 - GetNextRequest
 - GetNextResponse

## Message Types supported but lacking any unit test
The following OMCI message types currently have been coded but do not
have any unit test coverage.

 - StartSoftwareDownloadResponse
 - DownloadSectionRequest
 - DownloadSectionResponse
 - EndSoftwareDownloadRequest
 - EndSoftwareDownloadResponse
 - ActivateSoftwareRequest
 - ActivateSoftwareResponse
 - CommitSoftwareRequest
 - CommitSoftwareResponse
 - GetCurrentDataRequest
 - GetCurrentDataResponse
 - AlarmNotification
 
## Message Types not yet supported

The following OMCI message types currently have not been coded.

 - TestResult
 - TestRequest
 - TestResponse
 - SetTableRequest
 - SetTableResponse

## Current user-test coverage

The _coverage.sh_ and _coverage.cmd_ scripts can be used to create code coverage support for the
library.  The current coverage (as of 2/11/2020) is:

| File            | Statement Coverage |
| --------------: | :---: |
| layers.go       | 100%  |
| mebase.go       | 87.5% |
| meframe.go      | 54.8% |
| messagetypes.go | 48.1% |
| omci.go         | 81.6% |

## Other outstanding items

Besides OMCI Message decode/serialization, and associated unit tests, the following items
would be needed or useful in a first official release of this library. Some changes are
to be done in the generated OMCI ME code as well.

 - Specific examples of how to use this library (expand upon DecodeEncode.go examples)
   Include unknown ME examples and how to catch various common or expected errors.  Until
   this is available, please take a look at how this library is used in my
   [onumock](https://github.com/cboling/onumock/README.md). There is a utilities subdirectory
   in the _onumock_ project that has some examples. One is a **very** crude OLT simulator that
   I wrote to help test the ONU Mock.
 - Support optional msg-types. (This was very recently fixed in the code generator).
 - Constraint checking (these are not yet fully parsed/provided by the OMCI code generated
   structs). This feature will hopefully be available in the near future.
 - Add Alarm Table Support (generated MEs also)
 - Add AVC flag for appropriate attributes
 - Support of the extended message format
 - For serialization, check early for message size exceeded
 - Add some type of logging support
 
The following would be 'nice' to have but are not necessary for initial code release
 - Extended message support
 - MIC Encode/Decode support
 
Also searching through the code for _TODO_ statements will also yeild additional areas of
work to be performed.

## What is not provided by this library

This library is not a full OMCI stack for either an OLT or an ONU. It is focused primarily on
packet decode/serialization and a variety of structs and functions that are useful for handling
the creation of OMCI frames and handling decoded frames from the PON.

For an OLT-side OMCI stack, you would still need to write:
 - OMCI CC sender & receiver with appropriate timeout support
 - OLT State machines to support 
   - MIB Uploads/Audits/Resynchronization (and a MIB database implemention),
   - More sophisticated get & get-next support to make handle of MEs with
     lots of attributes or table attributes easy to handle and code,
   - Alarm Table support,
   - OMCI ME/Msg-Type capabilities inquiry,
   - Performance Monitoring collection (and initial time synchronization), 
   - Service implementation
   
For an ONU-side OMCI stack, you would still need to write:
   - OMCC implementation,
   - MIB Database,
   - Get-Next cache for table attributes,
   - MIB upload next cache for MIB uploads,
   - Generation of any alarms/AVC notifications,
   - Actually acting on the create/delete/get/set/... requests from an OLT