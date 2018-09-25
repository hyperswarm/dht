// This file is auto generated by the protocol-buffers compiler

/* eslint-disable quotes */
/* eslint-disable indent */
/* eslint-disable no-redeclare */
/* eslint-disable camelcase */

// Remember to `npm install --save protocol-buffers-encodings`
var encodings = require('protocol-buffers-encodings')
var varint = encodings.varint
var skip = encodings.skip

var Input = exports.Input = {
  buffer: true,
  encodingLength: null,
  encode: null,
  decode: null
}

var Output = exports.Output = {
  buffer: true,
  encodingLength: null,
  encode: null,
  decode: null
}

defineInput()
defineOutput()

function defineInput () {
  var enc = [
    encodings.varint,
    encodings.bytes
  ]

  Input.encodingLength = encodingLength
  Input.encode = encode
  Input.decode = decode

  function encodingLength (obj) {
    var length = 0
    if (defined(obj.type)) {
      var len = enc[0].encodingLength(obj.type)
      length += 1 + len
    }
    if (defined(obj.port)) {
      var len = enc[0].encodingLength(obj.port)
      length += 1 + len
    }
    if (defined(obj.localAddress)) {
      var len = enc[1].encodingLength(obj.localAddress)
      length += 1 + len
    }
    return length
  }

  function encode (obj, buf, offset) {
    if (!offset) offset = 0
    if (!buf) buf = Buffer.allocUnsafe(encodingLength(obj))
    var oldOffset = offset
    if (defined(obj.type)) {
      buf[offset++] = 8
      enc[0].encode(obj.type, buf, offset)
      offset += enc[0].encode.bytes
    }
    if (defined(obj.port)) {
      buf[offset++] = 16
      enc[0].encode(obj.port, buf, offset)
      offset += enc[0].encode.bytes
    }
    if (defined(obj.localAddress)) {
      buf[offset++] = 26
      enc[1].encode(obj.localAddress, buf, offset)
      offset += enc[1].encode.bytes
    }
    encode.bytes = offset - oldOffset
    return buf
  }

  function decode (buf, offset, end) {
    if (!offset) offset = 0
    if (!end) end = buf.length
    if (!(end <= buf.length && offset <= buf.length)) throw new Error("Decoded message is not valid")
    var oldOffset = offset
    var obj = {
      type: 0,
      port: 0,
      localAddress: null
    }
    while (true) {
      if (end <= offset) {
        decode.bytes = offset - oldOffset
        return obj
      }
      var prefix = varint.decode(buf, offset)
      offset += varint.decode.bytes
      var tag = prefix >> 3
      switch (tag) {
        case 1:
        obj.type = enc[0].decode(buf, offset)
        offset += enc[0].decode.bytes
        break
        case 2:
        obj.port = enc[0].decode(buf, offset)
        offset += enc[0].decode.bytes
        break
        case 3:
        obj.localAddress = enc[1].decode(buf, offset)
        offset += enc[1].decode.bytes
        break
        default:
        offset = skip(prefix & 7, buf, offset)
      }
    }
  }
}

function defineOutput () {
  var enc = [
    encodings.bytes
  ]

  Output.encodingLength = encodingLength
  Output.encode = encode
  Output.decode = decode

  function encodingLength (obj) {
    var length = 0
    if (defined(obj.peers)) {
      var len = enc[0].encodingLength(obj.peers)
      length += 1 + len
    }
    if (defined(obj.localPeers)) {
      var len = enc[0].encodingLength(obj.localPeers)
      length += 1 + len
    }
    return length
  }

  function encode (obj, buf, offset) {
    if (!offset) offset = 0
    if (!buf) buf = Buffer.allocUnsafe(encodingLength(obj))
    var oldOffset = offset
    if (defined(obj.peers)) {
      buf[offset++] = 10
      enc[0].encode(obj.peers, buf, offset)
      offset += enc[0].encode.bytes
    }
    if (defined(obj.localPeers)) {
      buf[offset++] = 18
      enc[0].encode(obj.localPeers, buf, offset)
      offset += enc[0].encode.bytes
    }
    encode.bytes = offset - oldOffset
    return buf
  }

  function decode (buf, offset, end) {
    if (!offset) offset = 0
    if (!end) end = buf.length
    if (!(end <= buf.length && offset <= buf.length)) throw new Error("Decoded message is not valid")
    var oldOffset = offset
    var obj = {
      peers: null,
      localPeers: null
    }
    while (true) {
      if (end <= offset) {
        decode.bytes = offset - oldOffset
        return obj
      }
      var prefix = varint.decode(buf, offset)
      offset += varint.decode.bytes
      var tag = prefix >> 3
      switch (tag) {
        case 1:
        obj.peers = enc[0].decode(buf, offset)
        offset += enc[0].decode.bytes
        break
        case 2:
        obj.localPeers = enc[0].decode(buf, offset)
        offset += enc[0].decode.bytes
        break
        default:
        offset = skip(prefix & 7, buf, offset)
      }
    }
  }
}

function defined (val) {
  return val !== null && val !== undefined && (typeof val !== 'number' || !isNaN(val))
}
