import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import validate from "validator";
import {appError} from "./handel/error.js";
import jwt from "jsonwebtoken";
import {asyncWrapper} from "./handel/asyncWrapper.js";
import bcrypt from "bcryptjs"
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import { fileTypeFromFile } from "file-type";
import fs from "fs"
import cors from "cors"



dotenv.config()

const app = express();
const port = process.env.PORT;
// const hostname = process.env.HOSTNAME;
const mongo_db = process.env.MONGO_DB;
const USER = "user";
const ADMIN = "admin";
const MANAGER = "manager";
const FAIL = "fail";
const ERROR = "error";
const SUCCESS= "success"
const routes = express.Router();
const aerror = new appError();
const seckret = process.env.SECKRET_KEY
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);





const verifyJWT = (req,res,next)=>{
    const authHeader = req.headers.authorization || req.headers.Authorization
    if(!authHeader){
        return res.status(400).json({
            status:FAIL,
            data:{msg:"not found any authorization"}
        })
    }
    const token = authHeader.split(' ')[1]
    try{
        const decode = jwt.verify(token,seckret)
        req.user = decode 
        next()
    }catch(err){
        return res.status(400).json({
            status:FAIL,
            data:{msg:"invalid token" , err}
        })
    }
}


const allowTo = (...roles) =>{
    return (req,res,next)=>{
        if(!req.user || !roles.includes(req.user.role)){
            return res.status(403).json({
                status:FAIL, 
                data:{msg:"not allwoed"}
            })
        }
        next()
    }
}



const allowOwnerOrAdmin = (req,res,next)=>{
    
    if(req.user.role === ADMIN || req.user._id === req.params.id){
        return next();
    }
    return res.status(403).json({
        status:FAIL,
        data:{msg:"not allowed"}
    })
}


const schem = mongoose.Schema(
    {
        fristName:{
            type:String,
            required:true,
            trim:true
        },
        lastName:{
            type:String,
            required:true,
            trim:true
        },
        email:{
            required:true,
            unique:true,
            lowercase:true,
            trim:true,
            type:String,
            validate:[validate.isEmail,"email not validate"]
        },
        password:{
            required:true,
            trim:true,
            type:String,
            minlength:8
        },
        role:{ 
            type:String,
            enum:[USER , ADMIN ,MANAGER],
            default :USER
        },
        avatar:{
            type:String,
            default:"./uploads/pexels-stefanstefancik-919606.jpg"
        }
    },
    {
        timestamps:true
    }
)

const mongodb = mongoose.model("user",schem , "userdata")

const fileFilter = (req,file,cb) =>{
    const fileType = file.mimetype.split('/')[0];
    if(fileType === 'image'){
        return cb(null,true)
    }else{
        return(aerror("file is require image",400,"error"),false)
    }
}

//curl -F "avatar=@virus.exe;type=image/png" http://localhost:3000/upload

const diskStorage = multer.diskStorage({
    destination: function(req,file,cb){
        console.log("FILE:", file);
        cb(null , "uploads")
    },
    filename: function(req,file,cb){
        const exc = file.mimetype.split('/')[1]
        const fileName = `user-${Date.now()}.${exc}`
        cb(null,fileName)
    }
})


const upload = multer({storage:diskStorage,fileFilter})




mongoose.connect(mongo_db)
    .then(()=>{
        console.log("connected mongodb")
    })
    .catch((err) => {
        console.log("ERROR -> ", err)
    })


app.use(express.json())
app.use("/api/users",routes)
app.use("/uploads",express.static(path.join(__dirname,"uploads")))
app.use(cors())

routes.post("/upload-avatar/:id",verifyJWT, allowOwnerOrAdmin, upload.single("avatar"), asyncWrapper(async(req,res)=>{    
    const typeFile = await fileTypeFromFile(req.file.path);

    console.log("Original Name:", req.file.originalname);
    console.log("MimeType:", req.file.mimetype);


    if (!typeFile || !typeFile.mime.startsWith("image/")) {
        fs.unlink(req.file.path, (err) => {
            if (err) console.log(err);
        });
        console.log("Real Type:", typeFile);
        return res.status(400).json({
            status: FAIL,
            msg:"only image files are allowed"
        })
    }

    res.json({
        status: SUCCESS,
        msg: "upload success",
        file: req.file.filename
    })
}))




//add user
routes.post("/register", asyncWrapper(async(req,res)=>{
        const {fristName,lastName,email,password} = req.body;
        const uemail = await mongodb.findOne({email})

        if(uemail){
            return res.status(400).json({status:FAIL ,data:{msg:"email arleady exite"}})
        }

        const passwordHash = await bcrypt.hash(password,10)

        const adduser = new mongodb({
            fristName,
            lastName,
            email,
            password: passwordHash
        });

        const token = jwt.sign({_id:adduser._id , role:adduser.role , email:adduser.email} , seckret , {expiresIn:"1w"})

        await adduser.save();

        res.status(201).json({
            status: SUCCESS,
            data: {
                msg: "user created successfully",
                user: {
                    _id: adduser._id,
                    firstName: adduser.fristName,
                    lastName: adduser.lastName,
                    role: adduser.role,
                    path: adduser.avatar,
                    token
                }
            }
        });
}));


//verify user

routes.post("/login",asyncWrapper(async(req,res)=>{

        const {email,password} = req.body

        if(!email || !password){
            return res.status(400).json({status:FAIL , data:{msg:"email and password are required"}})
        }

        const user = await  mongodb.findOne({email})

        if(!user){
            return res.status(400).json({status:FAIL , data:{msg:"email or password are error"}})
        }

        const passwordCheck = await bcrypt.compare(password,user.password)

        if(!passwordCheck){
            return res.status(400).json({status:FAIL , data:{msg:"email or password are error"}})
        }

        const token = jwt.sign({_id:user._id , role:user.role ,email:user.email} ,seckret , {expiresIn: "1h"})
        
        res.json({status:SUCCESS,data:{msg:"success to login" , token}})
        
    }))


//allusers
routes.get( "/" ,verifyJWT ,allowTo(ADMIN,MANAGER) ,asyncWrapper (async(req,res,next)=>{
        const query = req.query

        const page = query.page || 1;
        const limit = query.limit || 5;
        const skip = (page-1) * limit

        const allUsers = await mongodb.find({},{password:0 ,__v:0}).skip(skip).limit(limit);
            if(allUsers.length === 0){
                return next(aerror.create("not found any user" , 400 , FAIL))
            }
            res.json({status:SUCCESS , data:{allUsers}})
    })) 



//single user
routes.get("/user/:id", verifyJWT, allowOwnerOrAdmin, asyncWrapper (async(req,res)=>{
        const id = req.params.id;
        const ouser = await mongodb.findById(id);
        if(!ouser){
            return res.status(404).json({ status:FAIL , data:{msg: "not found this user"} })
        }
        res.json({status:SUCCESS , data:{ouser}})
    }))



// update user
routes.patch("/update/:id" ,verifyJWT, allowOwnerOrAdmin, asyncWrapper(async(req,res)=>{
        const id = req.params.id
        const {fristName,lastName} = req.body

        const suser = await mongodb.findOneAndUpdate({_id:id},{$set:{fristName,lastName}},{returnDocument:"after",projection:{password:0,__v:0}})
        
        if(!suser){
            return res.status(400).json({status:FAIL,data:{msg:"not found this user"}})
        }

        res.json({
            status:SUCCESS,
            data:{
                msg:"success to update",
                data:suser
            }
        })
    }))



// to access dbs and chanage role to admin to accass

routes.patch("/user/:id/role",verifyJWT, allowTo(ADMIN), asyncWrapper(async(req,res)=>{
    const {role} = req.body;
    const id = req.params.id;



    if (![USER, ADMIN, MANAGER].includes(role)) {
        return res.status(400).json({
            status: FAIL,
            data: {
                msg: "Invalid role"
            }
        });
    }
    
    const nuser = await mongodb.findById(id)
    if(!nuser){
        return res.status(404).json({
            status: FAIL,
            data: {
                msg: "User not found"
            }
        });
    }

    if (req.user._id === id) {
        return res.status(403).json({
            status: FAIL,
            data: {
                msg: "You cannot change your own role"
            }
        });
    }
    
    const adminCount = await mongodb.countDocuments({
        role: ADMIN
    });
    const user = await mongodb.findById(req.params.id);
    if (
        user.role === ADMIN &&
        role !== ADMIN &&
        adminCount === 1
    ) {
        return res.status(400).json({
            status: FAIL,
            data: {
                msg: "Cannot remove the last admin"
            }
        });
    }
    await mongodb.findByIdAndUpdate(id,{role}, { returnDocument: "after" });
    res.json({status:SUCCESS, data:{msg:"role updated"}})
}))


routes.patch("/me/change-password" , verifyJWT, asyncWrapper(async(req,res,next)=>{
    const {oldPassword, newPassword} = req.body
    if (!oldPassword || !newPassword) {
        return res.status(400).json({
            status: FAIL,
            data: {
                msg: "oldPassword and newPassword are required"
            }
        });
    }
    const userId = req.user._id;
    const user = await mongodb.findById(userId);
    if(!user){
        return res.status(404).json({
            status: FAIL,
            data: {
                msg: "User not found"
            }
        });
    }
    const checkUser = await bcrypt.compare(oldPassword,user.password)
    if(!checkUser){
        return res.status(403).json({
            status:FAIL,
            data:{
                msg:"oldPassword is woring"
            }
        })
    }

    if(oldPassword === newPassword){
        return res.status(400).json({
            status:FAIL,
            data:{
                msg:"new password cannot be the same as old password"
            }
        })
    }
    const passwordHash = await bcrypt.hash(newPassword,10)
    await mongodb.findByIdAndUpdate(req.user._id,{password: passwordHash})

    res.json({
        status:SUCCESS,
        data:"success to change password by you"
    })
}))



routes.patch("/change-password/:id", verifyJWT, allowTo(ADMIN,MANAGER),asyncWrapper(async(req,res)=>{
    const {password} = req.body
    if (!password) {
        return res.status(400).json({
            status: FAIL,
            data: {
                msg: "Password is required"
            }
        });
    }
    const id = req.params.id
    const passwordHash = await bcrypt.hash(password,10)
    await mongodb.findByIdAndUpdate(id,{password: passwordHash})
    res.json({
        status:SUCCESS,
        data:{
            msg:"success to change password by admin"
        }
    })
}))


routes.patch("/me/change-email", verifyJWT, asyncWrapper(async(req,res)=>{
    const id = req.user._id;
    const oldEmail = req.user.email;
    const {email} = req.body;

    if(oldEmail === email){
        return res.status(400).json({
            status:FAIL,
            data:{
                msg:"can't change to same email"
            }
        })
    }

    const emailExists = await mongodb.findOne({email})
    if(emailExists){
        return res.status(400).json({
            status:FAIL,
            data:{
                msg:"email arleady exists"
            }
        })
    }

    await mongodb.findByIdAndUpdate(id,{email})
    res.json({
        status:SUCCESS,
        data:{
            msg:"success to change email by you",
            email,
        }
    })
}))


routes.patch("/change-email/:id",verifyJWT, allowTo(ADMIN), asyncWrapper(async(req,res)=>{
    const id = req.params.id;
    const user = await mongodb.findById(id);
    if(!user){
        return res.status(404).json({
            status:FAIL,
            data:{
                msg:"can't find this user"
            }
        })
    }
    const oldEmail = user.email;
    const {email} = req.body;
    if(oldEmail === email){
        return res.status(400).json({
            status:FAIL,
            data:{
                msg:"can't change to same email"
            }
        })
    }
    await mongodb.findByIdAndUpdate(id,{email});
    res.json({
        status:SUCCESS,
        data:{
            msg:"success to update email by admin"
        }
    })
})) 

//delete user
routes.delete("/delete/:id", verifyJWT,allowOwnerOrAdmin,asyncWrapper(async(req,res)=>{
        const id = req.params.id
        const deluser = await mongodb.findByIdAndDelete(id)
        if(!deluser){
            return res.status(400).json({
                status:FAIL,
                data:{msg:"can't find this user"}
            })
        }
        res.json({status:SUCCESS,data:{msg:"success to delete"}})
    }))


// node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

app.use((err, req, res, next) => {

    res.status(err.status || 500).json({
        status:err.statusText || ERROR,
        data:{
            message: err.message
        }
    });
});


app.all("/*split", (req, res) => {
    res.status(404).json({
        status:ERROR,
        data:{
            message: "Route not found"
        }
    });
});



app.listen(port,()=>{
    console.log(`connected server -> http://localhost:${port}`)
})


