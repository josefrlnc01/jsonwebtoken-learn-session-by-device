import cors from 'cors'


export const corsMiddleware = () => cors({
   

    origin : (origin, callback) => {
         const ACCEPTED_ORIGINS = [
    'http://localhost:3000',
     'http://localhost:3000/register',
      'http://localhost:3000/login',
       'http://localhost:3000/logout'

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
