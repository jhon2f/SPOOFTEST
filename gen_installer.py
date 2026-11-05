# Rebuild installer.bin from installer.asm semantics, with BSOD fixes:
#  FIX #1: ObReferenceObjectByName DesiredAccess must be non-zero (SYNCHRONIZE|READ_CONTROL)
#  FIX #2: always ObDereferenceObject the driver object (no refcount leak)
#  FIX #3: validate original MajorFunction[14] (non-zero + canonical kernel VA) before patching;
#          NULL-guard DriverName.Buffer before dereferencing.
import re, struct

data = bytearray(open('installer_orig.bin','rb').read()) if False else None
