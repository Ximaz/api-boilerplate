import express from "express";
import dotenv from "dotenv";

dotenv.config();

const server = express();
const HOSTADDR = "0.0.0.0";
const PORT = parseInt(process.env["PORT"] as string);

if (undefined === PORT || isNaN(PORT))
    throw new Error("Missing or invalid port in environment variables.");

server.listen(PORT, HOSTADDR, function () {
    console.log(`REST API Started at http://${HOSTADDR}:${PORT}`);
});
