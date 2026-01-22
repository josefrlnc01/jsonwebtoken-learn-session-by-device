import cors from 'cors'
import express from 'express'
import jwt from 'jsonwebtoken'


const PORT = 3000
const app = express()
app.use(express.json())


function auth(req, res, next) {
    const headers = req.headers.authorization
    console.log(headers)
    const token = headers && headers.split(' ')[1]
    
    if (!token) {
        return res.status(401).json({message : 'No hay token en headers'})
    }

    try {
        const decoded = jwt.verify(token, clave_secreta)
       
        req.user = decoded
        next()
    } catch (error) {
        return res.status(401).json({message : 'No se puedo decodificar el token'})
    }
}


const corsMiddleware = () => cors({
   

    origin : (origin, callback) => {
         const ACCEPTED_ORIGINS = [
    'http://localhost:3000'
]
        if (ACCEPTED_ORIGINS.includes(origin)) {
            return callback(null, true)
        }
        if (!origin) {
            return callback(null, true)
        }

        return callback(new Error('Not allowed by cors'))
    }
})

app.use(corsMiddleware())
const clave_secreta ="4234234234213434244"

app.post('/login', (req, res) => {
    const {user, email} = req.body
    

    const token = jwt.sign({user, email}, clave_secreta, {
        expiresIn : '10m'
    })

    res.json({token})
})


app.get('/login', auth, (req, res) => {
    res.json({message : 'Hello World'})
})


app.listen(PORT, () => {
    console.log(`app listen on ${PORT}`)
})







