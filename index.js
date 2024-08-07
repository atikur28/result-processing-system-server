const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.a6wxvwg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const usersCollection = client
      .db("resultProcessingSystem")
      .collection("users");
    const resultsCollection = client
      .db("resultProcessingSystem")
      .collection("results");

    // jwt
    app.post("/jwt", async (req, res) => {
      const users = req.body;
      const token = jwt.sign(users, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "5h",
      });
      res.send({ token });
    });

    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "forbidden access!" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
        if (error) {
          return res.status(401).send({ message: "forbidden access!" });
        }
        req.decoded = decoded;
        next();
      });
    };

    // users
    app.get("/users", async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    // user admin verify
    app.get("/users/admin/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "unauthorized access" });
      }
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      let isAdmin = false;
      if (user) {
        isAdmin = user?.role === "admin";
      }
      res.send({ isAdmin });
    });

    // user teacher verify
    app.get("/users/manager/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "unauthorized access" });
      }
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      let isManager = false;
      if (user) {
        isManager = user?.role === "manager";
      }
      res.send({ isManager });
    });

    // user info post to database
    app.post("/users", async (req, res) => {
      const user = req.body;
      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: "User already exist" });
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    //user delete from database
    app.delete("/users/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });

    //teacher turn into admin
    app.patch("/users/admin/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          role: "admin",
        },
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // admin turn into user
    app.patch("/users/user/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          role: "user",
        },
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // user turn into manager
    app.patch("/users/manager/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          role: "manager",
        },
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // results
    app.get("/results", async (req, res) => {
      const result = await resultsCollection.find().toArray();
      res.send(result);
    });

    app.get("/results/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await resultsCollection.findOne(query);
      res.send(result);
    });

    //updated Results
    app.patch("/results/:id", async (req, res) => {
      const item = req.body;
      const id = req.params.id;
      const filter = {_id: new ObjectId(id) };
    
      console.log('Request Body:', item);
      console.log('Request ID:', id);
      
      const updatedDoc = {
      $set:{
        name:item.name,
        fatherName:item.fatherName,
        motherName:item.motherName,
        birthDate: item.birthDate,
        rollNo:item.rollNo,
        registrationNo:item.registrationNo,
        teacherEmail: item.teacherEmail,
        department:item.department,
        semester:item.semester,
        session:item.session,
        studentType:item.studentType,
        institute:item.institute,
        subjects:item.subjects,
      }
    }

      const result = await resultsCollection.updateOne(filter,updatedDoc)
      res.send(result)
    });
    


    // students result post from teacher to database
    app.post("/results", verifyToken, async (req, res) => {
      const resultInfo = req.body;
      const result = await resultsCollection.insertOne(resultInfo);
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Result processing system server is running...");
});

app.listen(port, () => {
  console.log(`Result processing system is running on port: ${port}`);
});
