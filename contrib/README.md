# etl2pcapng contrib

These files are not required for developing, building or using etl2pcapng, but they might be useful
nonetheless.

## EtlStructs.h

Descriptions of common structures in `.etl` files in the form of a C header. Can be used by some
software packages, including some hex editors, to dissect the format and help with the development
of deserialization code.

## Microsoft-Windows-NDIS-PacketCapture.manifest.xml

The instrumentation manifest of the `Microsoft-Windows-NDIS-PacketCapture` provider.

The definition itself is contained in `ndiscap.sys` in a resource of type `WEVT_TEMPLATE1`, but its
format is not well-understood. The XML representation has been obtained using
[PerfView](https://github.com/Microsoft/perfview) by starting it as follows:

    .\perfview UserCommand DumpRegisteredManifest "Microsoft-Windows-NDIS-PacketCapture"
