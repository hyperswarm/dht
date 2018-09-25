const { DHT } = require('dht-rpc')
const recordCache = require('record-cache')
const { PeersInput, PeersOutput } = require('./messages')
const peers = require('ipv4-peers')
const sodium = require('sodium-universal')
const hashlru = require('hashlru')

module.exports = opts => new HyperDHT(opts)

class HyperDHT extends DHT {
  constructor (opts) {
    super(opts)

    const peers = recordCache({
      maxSize: 65536,
      maxAge: 12 * 60 * 1000
    })

    const immutableKeys = hashlru(1024)
    const mutableKeys = hashlru(1024)

    this._peers = peers
    this._immutableKeys = immutableKeys
    this._mutableKeys = mutableKeys

    const onpeers = this._onpeers.bind(this)

    this.once('close', peers.destroy.bind(peers))
    this.command('peers', {
      inputEncoding: PeersInput,
      outputEncoding: PeersOutput,
      update: onpeers,
      query: onpeers
    })

    this.command('immutable-keys', {
      inputEncoding: ImmutableKeysInput,
      outputEncoding: ImmutableKeysOutput,
      update (query, cb) {
        const value = query.value

        if (value.salt && !(value.salt.length >= 16 && value.salt.length <= 32)) return cb(new Error('Invalid salt'))

        const key = hash(value.value, value.salt)
        if (!query.target.equals(key)) return cb(new Error('Invalid target'))

        immutableKeys.put(key.toString('hex'), value.value)
        cb(null)
      },
      query (query, cb) {
        const value = immutableKeys.get(query.target.toString('hex'))
        cb(null, { value })
      }
    })
  }

  lookup (key, query, cb) {
    if (typeof query === 'function') return this.lookup(key, null, query)
    if (!query) query = {}
    const port = query.port
    const localAddress = query.localAddress ? peers.encode([ query.localAddress ]) : null
    return this.query('peers', key, { port, localAddress }, cb).map(mapPeers.bind(null, localAddress))
  }

  announce (key, ann, cb) {
    if (typeof ann === 'function') return this.announce(key, null, ann)
    if (!ann) ann = {}
    const port = ann.port
    const localAddress = ann.localAddress ? peers.encode([ ann.localAddress ]) : null
    return this.queryAndUpdate('peers', key, { port, localAddress }, cb).map(mapPeers.bind(null, localAddress))
  }

  unannounce (key, ann, cb) {
    if (typeof ann === 'function') return this.unannounce(key, null, ann)
    if (!ann) ann = {}
    const port = ann.port
    const localAddress = ann.localAddress ? peers.encode([ ann.localAddress ]) : null
    this.update('peers', key, { port, localAddress, unannounce: true }, cb)
  }

  _onpeers (query, cb) {
    const value = query.value || {}
    const from = {
      port: value.port || query.node.port,
      host: query.node.host
    }

    if (!(from.port > 0 && from.port < 65536)) return cb(new Error('Invalid port'))

    const localRecord = value.localAddress
    const remoteRecord = peers.encode([ from ])

    const remoteCache = query.target.toString('hex')
    const localCache = localRecord &&
      remoteCache + '@local.' + localRecord.slice(0, 2).toString('hex')

    const localSuffix = localRecord && localRecord.slice(2)

    if (query.type === DHT.QUERY) {
      const local = localCache ? filter(this._peers.get(localCache, 64), localSuffix) : []
      const remote = filter(this._peers.get(remoteCache, 128 - local.length), remoteRecord)
      this.emit('lookup', query.target, from)

      return cb(null, {
        peers: remote.length ? Buffer.concat(remote) : null,
        localPeers: local.length ? Buffer.concat(local) : null
      })
    }

    if (value.unannounce) {
      if (remoteRecord) this._peers.remove(remoteCache, remoteRecord)
      if (localRecord) this._peers.remove(localCache, localSuffix)
      this.emit('unannounce', query.target, from)
    } else {
      if (remoteRecord) this._peers.add(remoteCache, remoteRecord)
      if (localRecord) this._peers.add(localCache, localSuffix)
      this.emit('announce', query.target, from)
    }

    cb(null, null)
  }
}

function filter (list, item) {
  if (!item) return list

  for (var i = 0; i < list.length; i++) {
    if (list[i].equals(item)) {
      list[i] = list[list.length - 1]
      list.pop()
      break
    }
  }

  return list
}

function mapPeers (prefix, data) {
  const v = data.value
  if (!v || (!v.peers && !v.localPeers)) return null

  try {
    return {
      node: data.node,
      peers: v.peers && peers.decode(v.peers),
      localPeers: prefix && v.localPeers && decodeLocalPeers(prefix, v.localPeers)
    }
  } catch (err) {
    return null
  }
}

function decodeLocalPeers (prefix, buf) {
  const host = prefix[0] + '.' + prefix[1] + '.'
  const peers = []

  if (buf.length & 3) return null

  for (var i = 0; i < buf.length; i += 4) {
    const port = buf.readUInt16BE(i + 2)
    if (!port) return null
    peers.push({
      host: host + buf[i] + '.' + buf[i + 1],
      port
    })
  }

  return peers
}

function hash (val, salt) {
  const out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(out, val, salt)
  return out
}
