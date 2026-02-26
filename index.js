(async () => {
    "use strict";

    // Dependencies
    const client = await require("./modules/mongodb.js")
    const simpleAES256 = require("simple-aes-256")
    const cookieParser = require("cookie-parser")
    const compression = require("compression")
    const { ObjectId } = require("mongodb")
    const requestIP = require("request-ip")
    const { parse } = require("smol-toml")
    const express = require("express")
    const hashJS = require("hash.js")
    const helmet = require("helmet")
    const cryptr = require("cryptr")
    const path = require("path")
    const xss = require("xss")
    const fs = require("fs")

    // Variables
    const config = parse(fs.readFileSync("./config.toml", "utf8"))
    const cT = new cryptr(config.security.cookieMasterKey, { encoding: config.security.cookieEncoding, pbkdf2Iterations: config.security.cookiePBKDF2Iterations, saltLength: config.security.cookieSaltLength })
    const web = express()

    const database = client.db(config.database.databaseName)
    const users = database.collection(config.database.usersCollectionName)
    const contacts = database.collection(config.database.contactsCollectionName)

    // Functions
    const SHA512 = (string) => { return hashJS.sha512().update(string).digest("hex") }
    const dS = async (session) => {
        try {
            const sessionData = JSON.parse(cT.decrypt(session.d))
            return sessionData
        } catch { return false }
    }

    const setCookie = (res, data) => {
        res.cookie("d", data, {
            maxAge: 12 * 60 * 60 * 1000, // 12 hours
            httpOnly: true,
            secure: process.env.NODE_ENV === "production"
        })
    }

    const aes256E = (password, string) => {
        return simpleAES256.encrypt(password, string).toString("hex")
    }

    const aes256D = (password, string) => {
        try {
            return simpleAES256.decrypt(password, Buffer.from(string, "hex")).toString("utf8")
        } catch {
            return string
        }
    }

    const decryptContact = (key, contact) => {
        return {
            ...contact,
            alias: contact.alias ? aes256D(key, contact.alias) : "",
            connections: (contact.connections || []).map(c => ({
                source: c.source ? aes256D(key, c.source) : "",
                contact: c.contact ? aes256D(key, c.contact) : ""
            })),
            relations: (contact.relations || []).map(r => ({
                contact: r.contact ? aes256D(key, r.contact) : "",
                label: r.label ? aes256D(key, r.label) : ""
            })),
            publicKey: contact.publicKey ? aes256D(key, contact.publicKey) : "",
            note: contact.note ? aes256D(key, contact.note) : ""
        }
    }

    // Configuration
    //* Express
    web.use(helmet.xssFilter(), helmet.xDnsPrefetchControl(), helmet.xXssProtection(), helmet.hidePoweredBy(), helmet.frameguard({ action: "deny" }), helmet.noSniff(), helmet.hsts(), helmet.referrerPolicy())
    web.set("views", path.join(__dirname, "views"))
    web.use(compression({ level: 1 }))
    web.set("view engine", "ejs")
    web.use(cookieParser())
    web.use(express.json())

    // Main
    web.get("/login",async (req, res, next)=>{
        if((await dS(req.cookies))) return res.redirect("/dashboard")
        next()
    })

    web.get("/register", async(req, res, next)=>{
        if((await dS(req.cookies))) return res.redirect("/dashboard")
        next()
    })
    
    web.get("/logout", async(req, res) => {
        if(!(await dS(req.cookies))) return res.redirect("/login")
        res.clearCookie("d").redirect("/")
    })

    web.get("/delete-account", async (req, res) => {
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.redirect("/login")

        await users.deleteOne({ hashedUsername: SHA512(cookieData.username) })
        await contacts.deleteMany({ username: SHA512(cookieData.username) })
        res.redirect("/")
    })

    //* API
    web.post("/api/login", async (req, res) => {
        if((await dS(req.cookies))) return res.send("1")

        //* Variables
        const ip = requestIP.getClientIp(req)
        const { username, password } = req.body
        const hashedUsername = SHA512(username), hashedPassword = SHA512(password)
        var accountData = await users.findOne({
            hashedUsername,
            password: hashedPassword
        })

        //* Validations
        if (!username || !password) return res.send("0")
        if (!accountData) return res.send("0")

        //* Core
        const now = new Date()
        const formattedDate = now.toLocaleString("en-US", {
            weekday: "long",
            year: "numeric",
            month: "long",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        })

        await users.updateOne({
            hashedUsername,
            password: hashedPassword
        }, {
            $push: {
                loginHistory: {
                    ip: aes256E(password, ip),
                    date: aes256E(password, formattedDate)
                }
            }
        })

        accountData = await users.findOne({
            hashedUsername,
            password: hashedPassword
        }) // Update again to get the pushed login history.

        setCookie(res, cT.encrypt(JSON.stringify({
            username: aes256D(password, accountData.username),
            password: password,
            loginHistory: accountData.loginHistory.map((d) => {
                return {
                    ip: aes256D(password, d.ip),
                    date: aes256D(password, d.date)
                }
            })
        })))

        res.send("1")
    })

    web.post("/api/register", async (req, res) => {
        if((await dS(req.cookies))) return res.send("1")

        //* Variables
        var { username, password } = req.body
        if(!username) return res.send("0")
        username = username.replace(/[^a-zA-Z0-9]/g, "")
        const hashedUsername = SHA512(username), hashedPassword = SHA512(password)
        const accountData = await users.findOne({
            hashedUsername
        })

        //* Validations
        if (accountData) return res.send("3") // An account with that username already exists.
        if (!password) return res.send("0")
        if (username.length > 35) return res.send("2") // Username too long. Max is 35

        //* Core
        await users.insertOne({
            hashedUsername: hashedUsername,
            username: aes256E(password, xss.filterXSS(username)),
            password: hashedPassword,
            loginHistory: []
        })

        res.send("1")
    })

    web.use("/dashboard", async (req, res) => {
        // Variables
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.redirect("/login")

        // Core
        const userContacts = await contacts.find({ username: SHA512(cookieData.username) }).toArray()
        const decryptedContacts = userContacts.map(c => decryptContact(cookieData.username, c))
        res.render("dashboard", { user: cookieData, contacts: decryptedContacts })
    })

    web.use("/contacts", async (req, res) => {
        // Variables
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.redirect("/login")

        // Core
        const userContacts = await contacts.find({ username: SHA512(cookieData.username) }).toArray()
        const decryptedContacts = userContacts.map(c => decryptContact(cookieData.username, c))
        res.render("contacts", { user: cookieData, contacts: decryptedContacts })
    })

    web.use("/graph", async (req, res) => {
        // Variables
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.redirect("/login")

        // Core
        const userContacts = await contacts.find({ username: SHA512(cookieData.username) }).toArray()
        const decryptedContacts = userContacts.map(c => decryptContact(cookieData.username, c))
        res.render("graph", { user: cookieData, contacts: decryptedContacts })
    })

    web.post("/api/contacts", async (req, res) => {
        // Variables
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.send("0")

        const { alias, connections, relations, publicKey, note } = req.body

        // Validations
        if (alias.length > 25) return res.send("0")
        if (publicKey && publicKey.length > 5200) return res.send("0")
        if (note && note.length > 1000) return res.send("0")

        const existingContacts = await contacts.find({ username: SHA512(cookieData.username) }).toArray()
        const existingAliases = existingContacts.map((c) => decryptContact(cookieData.username, c).alias)
        const safeAlias = xss.filterXSS(alias.replace(/[^a-zA-Z0-9]/g, "")).substring(0, 25)

        // Core
        await contacts.insertOne({
            username: SHA512(cookieData.username),
            alias: aes256E(cookieData.password, safeAlias),
            connections: connections.map((d) => {
                const s = xss.filterXSS(d.source).replace(/[^a-zA-Z0-9]/g, "").substring(0, 20)
                const c = xss.filterXSS(d.contact).substring(0, 60)
                return { source: aes256E(cookieData.password, s), contact: aes256E(cookieData.password, c) }
            }),
            relations: relations.map((d) => {
                const clabel = xss.filterXSS(d.label).substring(0, 14)
                return { contact: xss.filterXSS(d.contact), label: clabel }
            }).filter((d, index, self) =>
                d.contact !== safeAlias &&
                existingAliases.includes(d.contact) &&
                index === self.findIndex((t) => t.contact === d.contact)
            ).map(d => ({ contact: aes256E(cookieData.password, d.contact), label: aes256E(cookieData.password, d.label) })),
            publicKey: publicKey ? aes256E(cookieData.password, xss.filterXSS(publicKey).substring(0, 5200)) : "",
            note: note ? aes256E(cookieData.password, xss.filterXSS(note).substring(0, 1000)) : "",
            createdAt: new Date()
        })

        res.send("1")
    })

    web.put("/api/contacts/:id", async (req, res) => {
        // Variables
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.send("0")

        const { alias, connections, relations, publicKey, note } = req.body

        // Validations
        if (alias.length > 25) return res.send("0")
        if (publicKey && publicKey.length > 5200) return res.send("0")
        if (note && note.length > 1000) return res.send("0")

        const existingContacts = await contacts.find({ username: SHA512(cookieData.username) }).toArray()
        const existingAliases = existingContacts.map(c => decryptContact(cookieData.username, c).alias)
        const safeAlias = xss.filterXSS(alias.replace(/[^a-zA-Z0-9]/g, "")).substring(0, 25)

        /**
         * Max of alias is 25.
         * Max of connections name is 20, field is 60.
         * Max of relations label is 14.
         * Max of public key is 5200.
         * Max of note is uh 1000, duh.
         */

        // Core
        const cleanConnections = connections.map((d) => {
            const s = xss.filterXSS(d.source).replace(/[^a-zA-Z0-9]/g, "").substring(0, 20)
            const c = xss.filterXSS(d.contact).substring(0, 60)
            return { source: aes256E(cookieData.password, s), contact: aes256E(cookieData.password, c) }
        })

        const cleanRelations = relations.map((d) => {
            const clabel = xss.filterXSS(d.label).substring(0, 14)
            return { contact: xss.filterXSS(d.contact), label: clabel }
        }).filter((d, index, self) =>
            d.contact !== safeAlias &&
            existingAliases.includes(d.contact) &&
            index === self.findIndex((t) => t.contact === d.contact)
        ).map(d => ({ contact: aes256E(cookieData.password, d.contact), label: aes256E(cookieData.password, d.label) }))

        try {
            await contacts.updateOne(
                { _id: new ObjectId(req.params.id), username: SHA512(cookieData.username) },
                {
                    $set: {
                        alias: aes256E(cookieData.password, safeAlias),
                        connections: cleanConnections,
                        relations: cleanRelations,
                        publicKey: publicKey ? aes256E(cookieData.password, xss.filterXSS(publicKey).substring(0, 5200)) : "",
                        note: note ? aes256E(cookieData.password, xss.filterXSS(note).substring(0, 1000)) : "",
                        updatedAt: new Date()
                    }
                }
            )
            res.send("1")
        } catch {
            res.send("0")
        }
    })

    web.delete("/api/contacts/:id", async (req, res) => {
        // Variables
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.send("0")

        // Core
        try {
            await contacts.deleteOne({
                _id: new ObjectId(req.params.id),
                username: SHA512(cookieData.username)
            })
            res.send("1")
        } catch {
            res.send("0")
        }
    })

    web.get("/api/network-data", async (req, res) => {
        // Variables
        const cookieData = await dS(req.cookies)
        if (!cookieData) return res.status(401).json({ error: "Unauthorized" })

        // Core
        const userContacts = await contacts.find({ username: SHA512(cookieData.username) }).toArray()
        const decryptedContacts = userContacts.map((c) => decryptContact(cookieData.username, c))
        res.json({ user: cookieData, contacts: decryptedContacts })
    })

    //* Core
    web.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }))
    web.listen(config.web.port, () => console.log(`ShadowNetwork is running. Port: ${config.web.port}`))
})()