import React from 'react';
import express from 'express';
import mongoose from 'mongoose';

import bcryptjs from 'bcryptjs';
import User from './Models/usermodel.js'
import jwt from 'jsonwebtoken';
import { use } from 'react';

const app=express();

app.use(express.json());

mongoose.connect('mongodb://127.0.0.1:27017/AuthenticationDb?directConnection=true')
.then(()=>console.log('Authentication Database Connected'))
.catch((error)=>console.log('Database Not Connected'));



app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role  
    });
    await newUser.save();

    res.status(200).json({ message: 'User Created Successfully' });
  } catch (error) {
    res.status(201).json({ message: 'User Not Created' });
  }
});


app.post('/login',async(req,res)=>{
    try {
        const {email,password}=req.body;
        
        const user=await User.findOne({email});
        if(!user)
        {
            return res.status(404).json({message:'User Not Found'});
        }
        const isMatch=await bcryptjs.compare(password,user.password);
        
        if(!isMatch)
            { return res.status(401).json({message:'Incorrect Password'});
    }
        const token=jwt.sign({id:user._id , role: user.role}, "secretkey", {expiresIn:"1h"});
        res.status(200).json({message:'Login Successfull',token});
    } catch (error) {
        res.status(202).json({message:'Not Login Successfully'});
    }
})


function auth(req,res,next){
    const token=req.header("Authorization")?.replace("Bearer","");
    if(!token) return   res.status(401).json({message:'No Token , Access Denied'});
    try {
        const verified=jwt.verify(token,"secretkey");
        req.user=verified;
        next();
    } catch (error) {
        res.status(400).json({message:'Invalid Token'});
    }
}

app.get('/profile', auth, async(req,res)=>{
    const user=await User.findById(req.user.id).select("-password");
    res.json(user);
});




function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admins only' });
  }
  next();
}


app.get('/admin', auth, isAdmin, (req, res) => {
  res.json({ message: 'Welcome Admin!' });
});



app.listen(3939,()=>{
    console.log('Server running at http://127.0.0.1:3939');
});

