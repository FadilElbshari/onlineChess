import express from 'express';
import session from 'express-session';
import path from 'path'
import { createServer } from 'http';
import { Server } from 'socket.io';
import mysql from 'mysql2'
import bcrypt from "bcrypt"
import dotenv from 'dotenv';

dotenv.config();


class MatchMaking {
  constructor(io) {
    this.io = io;
    this.queue = [];
    this.activeMatches = new Map();
  }

  startClock(gameId) {
    const match = this.activeMatches.get(gameId);
    if (!match) return;

    // Initialize clock data if not already set
    if (!match.clock) {
      match.clock = {
        whiteTime: 300, // 5 minutes in seconds for white
        blackTime: 300, // 5 minutes in seconds for black
        activeColor: 'white',
      };
    }

    match.clock.timer = setInterval(() => {
      const clock = match.clock;
      if (clock.activeColor === 'white') {
        clock.whiteTime--;
      } else {
        clock.blackTime--;
      }

      // Emit clock updates to clients
      io.to(`game_${gameId}`).emit('clockUpdate', {
        whiteTime: clock.whiteTime,
        blackTime: clock.blackTime,
      });

      // Handle timeout
      if (clock.whiteTime <= 0 || clock.blackTime <= 0) {
        clearInterval(clock.timer);
        const result = clock.whiteTime <= 0 ? 'black' : 'white'; // Winning color
        this.endGame(gameId, `${result} wins on time`);
      }
    }, 1000);

  }

  stopClock(gameId) {
    const match = this.activeMatches.get(gameId);
    if (match?.clock?.timer) {
      clearInterval(match.clock.timer);
    }
  }

  switchClock(gameId) {
    const match = this.activeMatches.get(gameId);
    if (!match || !match.clock) return;

    match.clock.activeColor = match.clock.activeColor === 'white' ? 'black' : 'white';
  }

  addToQueue(socket, userId) {
    this.removeFromQueue(userId);

    this.queue.push({
      socket,
      userId
    });

    return this.tryMatch();
  }

  removeFromQueue(userId) {
    this.queue = this.queue.filter(player => player.userId !== userId);
  }

  async tryMatch() {
    if (this.queue.length >= 2) {
      const player1 = this.queue.shift();
      const player2 = this.queue.shift();
      try {

        const initialFEN = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"; // Initial FEN for the game
        const initialFenHistory = JSON.stringify([initialFEN]);
        const moves = JSON.stringify([])
        const clockStartingTime = 300
        // Create game in database
        const [result] = await pool.query(
          "INSERT INTO games (player1_id, player2_id, outcome, current_fen, fen_history, moves, player1_clock, player2_clock) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          [
            player1.userId,
            player2.userId,
            0,
            initialFEN,
            initialFenHistory,
            moves,
            clockStartingTime,
            clockStartingTime

          ]
        );

        const gameId = result.insertId;
        const match = {
          gameId,
          white: player1,
          black: player2
        };

        player1.socket.join(`user_${player1.userId}`);
        player2.socket.join(`user_${player2.userId}`);

        this.activeMatches.set(gameId, match);

        // Notify players

        console.log("reached")
        io.to(`user_${player1.userId}`).emit('matchFound', {
          gameId,
          color: 'white',
          opponentId: player2.userId
        });

        io.to(`user_${player2.userId}`).emit('matchFound', {
          gameId,
          color: 'black',
          opponentId: player1.userId
        });

        // Join game room
        player1.socket.join(`game_${gameId}`);
        player2.socket.join(`game_${gameId}`);

        this.startClock(gameId)

        return match;
      } catch (error) {
        console.error('Error creating game:', error);
        // Put players back in queue if database insertion fails
        this.queue.unshift(player2);
        this.queue.unshift(player1);
        return null;
      }
    }
    return null;
  }

  getPlayerGame(userId) {
    for (const [gameId, match] of this.activeMatches) {
      if (match.white.userId === userId || match.black.userId === userId) {
        return { gameId, match };
      }
    }
    return null;
  }

  async endGame(gameId, result) {
    // Handle game-over logic and notify clients
    await pool.query(
      "UPDATE games SET outcome = ? WHERE game_id = ?",
      [1, gameId]  // data.result should be 'checkmate' or 'stalemate'
    );

    this.io.to(`game_${gameId}`).emit('gameOverBroad', { result });
    this.stopClock(gameId);
    this.activeMatches.delete(gameId);
  }

}




const saltRounds = 10;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
}).promise();


const wrap = (expressMiddleWare) => (socket, next) => (expressMiddleWare(socket.request, {}, next));


const loggedInUsers = []

const app = express();
const PORT = process.env.PORT;
const server = createServer(app);
const io = new Server(server);

const matchmaking = new MatchMaking(io);


const __dirname = path.resolve();
app.use(express.static(path.join(__dirname, 'files')));

const sessionMiddleware = session({
  
  reconnection: true,
  reconnectionDelay: 1000, 
  reconnectionAttempts: 5,
  reconnectionDelayMax: 5000,
  randomizationFactor: 0.5,
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 }
})

app.use(sessionMiddleware)
app.use(express.json());
io.use(wrap(sessionMiddleware));


const searchUser = async (username) => {
  const [rows, fields] = await pool.query("SELECT * FROM USERS WHERE username = ?", [username]);
  return rows
}

const createUser = async (username, password, email) => {
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const result = await pool.query("INSERT INTO USERS (username, email, password) VALUES (?, ?, ?);", [username, email, hashedPassword]);
  return result[0]
}

const getHash = async (username) => {
  const result = await pool.query("SELECT password FROM USERS WHERE username = ?", [username]);
  return result[0][0].password;
}




//===================================ROUTES===============================================

app.get('/', (req, res) => {
  req.session.name = "Blah"
  return res.sendFile(path.join(__dirname, 'files', 'home.html'));
});

// Add this with your other routes
app.get('/game/:gameId/:color', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/'); // Redirect to home if not logged in
  }
  return res.sendFile(path.join(__dirname, 'files', 'game.html'));
});


app.get('/play', (req, res)=> {
  return res.sendFile(path.join(__dirname, 'files', 'chess.html'))
})


app.get('/api/check-session', (req, res) => {
  if (req.session.user) {
    return res.json({ loggedIn: true, username: req.session.user });
  } else {
    return res.json({ loggedIn: false });
  }
});

app.get("/playnow", (req, res)=>{
  return res.sendFile(path.join(__dirname, 'files', 'chess.html'));
})


app.post('/api/login', async (req, res) => {

  try {

    const { username, password } = req.body
    const foundUser = await searchUser(username)

    if (!foundUser) {
      return res.status(404).json({ message: "User not Found" })
    }

    const receivedHash = await getHash(username);
    const isMatch = await bcrypt.compare(password, receivedHash);

    if (isMatch) {

      req.session.user = {
        id: foundUser[0].ID,
        username: foundUser[0].username,
        email: foundUser[0].email,
      };


      req.session.save((err) => {
        if (err) {
          console.error('Session save failed:', err);
          return res.status(500).json({ message: "Failed to save session" });
        }

        return res.json({ message: "Login successful" });
      });

    } else {
      return res.status(401).json({ message: "Incorrect password" });
    }

  } catch (err) {
    return res.status(500).json({ message: "Internal server error" });
  }


});

app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Create a new user
    const data = await createUser(username, password, email);
    if (!data) {
      return res.status(500).json({ message: "User creation failed" });
    }

    // Fetch the user details after creation
    const user = await searchUser(username);
    if (!user || user.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }


    req.session.user = {
      id: user[0].ID,
      username: user[0].username,
      email: user[0].email,
    };

    req.session.save((err) => {
      if (err) {
        console.error('Session save failed:', err);
        return res.status(500).json({ message: "Failed to save session" });
      }
      return res.status(201).json({ message: "Signup successful", user: req.session.user });
    });
  } catch (error) {
    console.error("Error during signup:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});


app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('connect.sid'); // Clear session cookie
    res.send('Logged out successfully');
  });
});


//===================================ROUTES_END=================================================



//===================================SOCKET===============================================
io.on("connection", (socket) => {

  console.log("Connection: ", socket.id)

  socket.on("reconnect", () => {
    const session = socket.request.session;
    console.log("Reconnection: ", socket.id)
    if (session?.user) {
      const userId = session.user.id;
      const playerGame = matchmaking.getPlayerGame(userId);
      if (playerGame) {
        const { gameId } = playerGame;
        socket.join(`game_${gameId}`);
        socket.emit("reconnected", { gameId });
      }
    }
  });
  

  socket.on("joinQueue", () => {
    const session = socket.request.session;
    if (!session.user) {
      socket.emit('error', { message: 'Must be logged in' });
      return;
    }

    const userId = session.user.id;
    matchmaking.addToQueue(socket, userId);

    console.log(`${session.user.username} has joined the queue`)

    socket.emit('waitingForMatch');
  });

  socket.on('joinGame', async (gameId) => {
    const session = socket.request.session;
    if (!session.user) return;

    try {
      // Check if user is part of this game
      const [rows] = await pool.query(
        `SELECT g.*, 
            p1.username as player1_username,
            p2.username as player2_username,
            g.moves
        FROM games g
        JOIN USERS p1 ON g.player1_id = p1.ID
        JOIN USERS p2 ON g.player2_id = p2.ID
        WHERE g.game_id = ? AND (g.player1_id = ? OR g.player2_id = ?)`,
        [gameId, session.user.id, session.user.id]
      );

      if (rows.length > 0) {
        socket.join(`game_${gameId}`);
        // Send initial game state
        socket.emit('gameState', {
          fen: rows[0].current_fen,
          moves: rows[0].moves,
          player1: {
            id: rows[0].player1_id,
            username: rows[0].player1_username
          },
          player2: {
            id: rows[0].player2_id,
            username: rows[0].player2_username
          }
        });
      } else {
        socket.emit('error', { message: 'Not authorized to join this game' });
      }
    } catch (error) {
      console.error('Error joining game:', error);
      socket.emit('error', { message: 'Failed to join game' });
    }
  });



  socket.on("move", async (data) => {
    const session = socket.request.session;
    if (!session.user) return;

    const userId = session.user.id;
    const playerGame = matchmaking.getPlayerGame(userId);

    if (playerGame) {
      const { gameId } = playerGame;
      const move = data.notation

      try {
        // Update game in database
        await pool.query(
          "UPDATE games SET current_fen = ?, fen_history = JSON_ARRAY_APPEND(fen_history, '$', ?), moves = JSON_ARRAY_APPEND(moves, '$', ?) WHERE game_id = ?",
          [data.fen, data.fen, data.displayMove, gameId]
        );

        matchmaking.switchClock(gameId);

        // Emit move to opponent
        socket.to(`game_${gameId}`).emit("move_update", {
          move: move,
          gameId: gameId,
        });
      } catch (error) {
        console.error('Error updating game:', error);
      }
    }
  });

  socket.on("gameOver", async (data) => {
    const session = socket.request.session;

    if (!session.user) return;

    try {
      const userId = session.user.id;
      const playerGame = matchmaking.getPlayerGame(userId);
      const { gameId } = playerGame;
      // Update game status in database


      //matchmaking.activeMatches.delete(gameId);
      matchmaking.endGame(gameId, data.quote)

      // Broadcast to the other player


    } catch (error) {
      console.error('Error updating game status:', error);
      socket.emit('error', { message: 'Failed to update game status' });
    }
  });
  socket.on("disconnect", () => {
    const session = socket.request.session;
    if (session?.user) {
      const userId = session.user.id;
      matchmaking.removeFromQueue(userId);

      const playerGame = matchmaking.getPlayerGame(userId);
      if (playerGame) {
        socket.to(`game_${playerGame.gameId}`).emit("opponentDisconnected");
      }
    }
  });


})
//===================================SOCKET_END===============================================

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});