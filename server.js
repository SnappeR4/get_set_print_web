require('dotenv').config()

const express    = require('express')
const mongoose   = require('mongoose')
const morgan     = require('morgan')
const bodyParser = require('body-parser')
const path = require('path');

const AppVersionRoute = require('./routes/appversion')
const ShowADRoute     = require('./routes/showad')
const AuthRoute = require('./routes/authRoutes');
//mongodb://localhost:27017/testdb
mongoose.connect(process.env.MONGO_URL)
const db = mongoose.connection
db.on('error', (err)=> {
    console.log(err)
})

db.once('open', ()=> {
    console.log('DB Connection Success')
})

const app = express()

app.use(morgan('dev'))
app.use(bodyParser.urlencoded({extended: true}))
app.use(bodyParser.json())

// Set the view engine (if using EJS)
app.set('view engine', 'ejs');

app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index');
});

const PORT = process.env.PORT || 8000

app.listen(PORT, ()=>{
    console.log('Server is running on port '+PORT)
})

app.use('/api/appversion', AppVersionRoute)
app.use('/api/showad', ShowADRoute)
app.use('/api/auth', AuthRoute);