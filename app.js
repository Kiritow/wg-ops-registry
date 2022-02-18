const koa = require('koa')
const koaRouter = require('koa-router')
const koaBodyParser = require('koa-bodyparser')
const koaJson = require('koa-json')
const crypto = require('crypto')

const app = new koa()
app.proxy = true
app.use(koaBodyParser())
app.use(koaJson())

const router = new koaRouter()

class SimpleStore {
    constructor() {
        this.store = new Map()
        this.expire = new Map()
    }

    isExpired(k) {
        if (this.expire.get(k) <= new Date()) {
            this.expire.delete(k)
            this.store.delete(k)

            return true
        }

        return false
    }

    has(k) {
        return (this.store.has(k) && !this.isExpired(k))
    }

    get(k) {
        if (!this.isExpired(k)) return this.store.get(k)
        return null
    }

    set(k, v, ttlMs) {
        this.store.set(k, v)
        this.expire.set(k, new Date(new Date().valueOf()+ttlMs))
    }
}

const simpleStore = new SimpleStore()

function verifySignature(pubkey, data, sig) {
    return crypto.verify("sha256", Buffer.from(data), {
        key: pubkey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
    }, Buffer.from(sig, 'base64'))
}

router.post('/ensure', (ctx) => {
    let { name, pubkey, wgkey, sig } = ctx.request.body
    if (!name || !pubkey || !wgkey || !sig) {
        ctx.body = {
            code: -1,
            message: 'invalid parameters',
        }
        return
    }

    if (!verifySignature(pubkey, wgkey, sig)) {
        ctx.body = {
            code: -1,
            message: 'invalid sign',
        }
        return
    }

})

router.post('/register', (ctx) => {
    let { name, pubkey, wgkey, peers, sig } = ctx.request.body
    if (!name || !pubkey || !wgkey || !peers || !sig) {
        ctx.body = {
            code: -1,
            message: 'invalid parameters',
        }
        return
    }
    let clientIp = ctx.request.ip

    if (!verifySignature(pubkey, wgkey, sig)) {
        ctx.body = {
            code: -1,
            message: 'invalid sign',
        }
        return
    }

    let validPeers = {}
    let invalidPeers = []
    Object.keys(peers).forEach((peerName) => {
        if (!simpleStore.has(peerName)) {
            invalidPeers.push(peerName)
        } else {
            validPeers[peerName] = peers[peerName]
        }
    })

    let thisInfo = simpleStore.get(name)
    if (thisInfo && thisInfo.pubkey != pubkey) {
        ctx.body = {
            code: -2,
            message: 'invalid token',
        }
        return
    }

    simpleStore.set(name, {
        pubkey,
        wgkey,
        peers: validPeers,
        ip: clientIp,
    }, 60 * 60 * 1000)

    console.log(`register name=${name},expires=${simpleStore.expire.get(name).toUTCString()}`)

    if(invalidPeers.length > 0) {
        ctx.body = {
            code: 1,
            message: `partial success, invalid peers: ${invalidPeers.join(',')}`
        }
    } else {
        ctx.body = {
            code: 0,
            message: 'success',
        }
    }
})

router.post('/refresh', (ctx) => {
    let { name, sig } = ctx.request.body
    if (!name || !sig) {
        ctx.body = {
            code: -1,
            message: 'invalid parameters',
        }
        return
    }
    let clientIp = ctx.request.ip

    let thisInfo = simpleStore.get(name)
    if (!thisInfo) {
        ctx.body = {
            code: -1,
            message: 'invalid client'
        }
        return
    }

    let {pubkey, wgkey} = thisInfo

    if (!verifySignature(pubkey, wgkey, sig)) {
        ctx.body = {
            code: -1,
            message: 'invalid sign',
        }
        return
    }

    thisInfo.ip = clientIp
    simpleStore.set(name, thisInfo, 60 * 60 * 1000)

    console.log(`refresh name=${name},expires=${new Date(simpleStore.expire.get(name)).toUTCString()}`)

    ctx.body = {
        code: 0,
        message: 'success',
    }
})

router.get('/query', (ctx) => {
    let {name} = ctx.query
    if (!name) {
        ctx.body = {
            code: -1,
            message: 'invalid parameters',
        }
        return
    }

    let thisInfo = simpleStore.get(name)
    if (!thisInfo) {
        ctx.body = {
            code: -1,
            message: 'invalid client'
        }
        return
    }

    console.log(`query name=${name}`)

    ctx.body = {
        code: 0,
        message: 'success',
        data: thisInfo,
    }
})

// debug
router.get('/list', (ctx) => {
    let obj = {}
    Array.from(simpleStore.store.keys()).forEach((k) => {
        obj[k] = simpleStore.store.get(k)
    })

    ctx.body = {
        code: 0,
        message: 'success',
        data: obj,
    }
})

app.use(router.routes()).use(router.allowedMethods())
app.listen(8888)
console.log('server started')
