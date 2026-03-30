const express=require('express');

const app=express();
app.get('/',(req,res)=>{
res.send("hello world")
})
app.get('/health',(req,res)=>{
res.send('health endpoint')
})
app.listen(5000,()=>{
console.log("https://localhost:5000");
})

