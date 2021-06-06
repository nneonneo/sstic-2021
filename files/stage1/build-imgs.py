import json

usbms = json.load(open('usbms.json'))
frames = {int(frame["_source"]["layers"]["frame"]["frame.number"]):frame for frame in usbms}

f1 = open('scsi/out0-905.img', 'wb')
f2 = open('scsi/out0-1307.img', 'wb')
f3 = open('scsi/out-all.img', 'wb')

for framenr in sorted(frames):
    frame = frames[framenr]
    if "scsi_raw" in frame["_source"]["layers"] and "scsi_sbc.opcode_raw" not in frame["_source"]["layers"]["scsi"]:
        reqframe = frames[int(frame["_source"]["layers"]["scsi"]["scsi.request_frame"])]
        opcode = int(frame["_source"]["layers"]["scsi"]["scsi_sbc.opcode"])
        if opcode not in (40, 42):
            continue
        
        lba = int(reqframe["_source"]["layers"]["scsi"]["scsi_sbc.rdwr10.lba"])
        reqlen = int(reqframe["_source"]["layers"]["scsi"]["scsi_sbc.rdwr10.xferlen"])
        data = bytes.fromhex(frame["_source"]["layers"]["scsi_raw"][0])
        print(framenr, opcode, lba, reqlen, data[:512].hex())

        if framenr <= 905:
            f1.seek(lba * 512)
            f1.write(data)
        if framenr <= 1307:
            f2.seek(lba * 512)
            f2.write(data)
        f3.seek(lba * 512)
        f3.write(data)
        if framenr > 1307:
            with open('scsi/write-%d-%d.bin' % (framenr, lba), 'wb') as outf:
                outf.write(data)
