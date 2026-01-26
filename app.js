import { app, PORT } from './server.js'
import express from 'express'
import jwt from 'jsonwebtoken'
import { corsMiddleware } from './middlewares/cors.js'
import { authToken } from './middlewares/authToken.js'
import dotenv from 'dotenv'
import {db} from './db/db.js'
dotenv.config()

app.use(express.json())
app.use(corsMiddleware())



//Esta clave secreta siempre debe definirse en .env y no debe ser accesible
const access_key = process.env.SECRET_ACCESS_KEY
const refresh_key = process.env.SECRET_REFRESH_KEY


//Inicio de sesión para obtención del token
app.post('/login', (req, res) => {
     const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email)
    
    //Firma del token con valores introducidos por el usuario + clave secreta
    //Nunca guardamos passwords
     const refreshToken = jwt.sign({id : user.id}, refresh_key, {
    expiresIn : '90d'
   })

    const accessToken = jwt.sign({
    id : user.id,
    role : 'user'
   }, access_key, {
    expiresIn : '10m'
   })


   
   res.cookie('refreshToken', refreshToken, {
    httpOnly : true,
    sameSite : 'strict'
   })


    //Devolvemos el token
    res.json({accessToken})
})


app.get('/login', authToken, (req, res) => {
    res.json({message : 'Hello World'})
})


//Usamos el middleware de autenticación en las rutas deseadas
app.get('/profile', authToken, (req, res) => {
  res.json({ message: 'Acceso permitido', user: req.user })
})



app.listen(PORT, () => console.log(`Listening on ${PORT}`))



app.post('/register', (req, res) => {
   const {email} = req.body

   const insertUser = db.prepare(`INSERT INTO users(email, refresh_token)
    VALUES (?, ?)
    `)
    insertUser.run(email, refreshToken)

     const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email)

   res.json({ user})
})


app.post('/refresh', (req, res) => {
    const refreshToken = req.cookies.refreshToken
    if (!refreshToken) return res.sendStatus(401)


    const user = db.prepare(`SELECT id, email FROM users
        WHERE refresh_token = (?)
        `).get(refreshToken)


        if (!user) return res.sendStatus(403)


            try {
                const decoded = jwt.verify(refreshToken, refresh_key)

                const newAccessToken = jwt.sign({id : decoded.id}, access_key, {
                    expiresIn : '10m'
                })
                res.json({accessToken : newAccessToken})
            } catch(error) {
                return res.sendStatus(403)
            }
})


app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken
    if (refreshToken) {
        const user = req.user
        db.prepare(`UPDATE USERS SET refresh_token = NULL
            WHERE refresh_token = ?
        `).run(refreshToken)
    }

    res.clearCookie('refreshToken')
    res.sendStatus(204)
})








