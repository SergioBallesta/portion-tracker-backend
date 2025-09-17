const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

// Importar fetch de la forma correcta
let fetch;
(async () => {
  fetch = (await import('node-fetch')).default;
})();

const app = express();

// Configurar trust proxy para Railway
app.set('trust proxy', 1);

// Middleware para parsear JSON
app.use(express.json());

// Rate limiting para auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // máximo 10 intentos por IP
  message: { error: 'Demasiados intentos, intenta de nuevo más tarde' }
});

// Configurar CORS
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }
    
    const allowedOrigins = [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'https://portion-tracker-frontend.vercel.app'
    ];
    
    const isVercelPreview = origin.includes('.vercel.app');
    const isAllowedOrigin = allowedOrigins.includes(origin);
    
    if (isAllowedOrigin || isVercelPreview) {
      callback(null, true);
    } else {
      console.log('CORS bloqueado para origen:', origin);
      callback(null, false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
}));

// CREDENCIALES Y CONFIGURACIÓN
const CLIENT_ID = process.env.FATSECRET_CLIENT_ID;
const CLIENT_SECRET = process.env.FATSECRET_CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET || 'desarrollo-secret-cambiar-en-produccion';
const DATABASE_URL = process.env.DATABASE_URL;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Faltan FATSECRET_CLIENT_ID o FATSECRET_CLIENT_SECRET');
}

// Configuración de PostgreSQL
let pool;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
  });
  
  // Crear tablas si no existen
  pool.query(`
    CREATE TABLE IF NOT EXISTS users (
		  id SERIAL PRIMARY KEY,
		  email VARCHAR(255) UNIQUE NOT NULL,
		  password_hash VARCHAR(255) NOT NULL,
		  is_verified BOOLEAN DEFAULT FALSE,
		  verification_code VARCHAR(6),
		  verification_expires TIMESTAMP,
		  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS email_whitelist (
		  id SERIAL PRIMARY KEY,
		  email VARCHAR(255) UNIQUE NOT NULL,
		  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		  added_by VARCHAR(255)
		);
    
    CREATE TABLE IF NOT EXISTS user_profiles (
	  user_id INTEGER PRIMARY KEY REFERENCES users(id),
	  first_name VARCHAR(100),
	  last_name VARCHAR(100),
	  birth_date DATE,
	  current_weight DECIMAL(5,2),
	  weight_history JSONB DEFAULT '[]',
	  meal_names JSONB,
	  meal_count INTEGER,
	  portion_distribution JSONB,
	  personal_foods JSONB,
	  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
    
    CREATE TABLE IF NOT EXISTS consumed_foods (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      date DATE,
      consumed_foods JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, date)
    );
  `).then(() => console.log('✅ Tablas creadas/verificadas en PostgreSQL'))
    .catch(err => console.error('Error creando tablas:', err));
} else {
  console.error('⚠️ DATABASE_URL no configurada - el sistema no funcionará correctamente');
}

// Función de migración para agregar columnas faltantes
const migrateDatabase = async () => {
  if (!pool) return;
  
  try {
    console.log('Ejecutando migraciones de base de datos...');
    
    // Verificar si las columnas existen y agregarlas si no
    await pool.query(`
      -- Agregar columnas de verificación si no existen
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT TRUE,
      ADD COLUMN IF NOT EXISTS verification_code VARCHAR(6),
      ADD COLUMN IF NOT EXISTS verification_expires TIMESTAMP;
      
      -- Marcar usuarios existentes como verificados
      UPDATE users SET is_verified = TRUE WHERE is_verified IS NULL;
      
      -- Crear tabla de whitelist si no existe
      CREATE TABLE IF NOT EXISTS email_whitelist (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        added_by VARCHAR(255)
      );
      
      -- Agregar emails existentes a la whitelist automáticamente
      INSERT INTO email_whitelist (email, added_by)
      SELECT email, 'auto-migration' FROM users
      ON CONFLICT (email) DO NOTHING;
    `);
    
    console.log('✅ Migraciones completadas exitosamente');
  } catch (error) {
    console.error('Error en migración:', error);
  }
};

// Modificar la inicialización del pool
if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
  });
  
  // Primero crear tablas base
  pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS user_profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      birth_date DATE,
      current_weight DECIMAL(5,2),
      weight_history JSONB DEFAULT '[]',
      meal_names JSONB,
      meal_count INTEGER,
      portion_distribution JSONB,
      personal_foods JSONB,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS consumed_foods (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      date DATE,
      consumed_foods JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, date)
    );
  `).then(async () => {
    console.log('✅ Tablas base creadas/verificadas');
    // Ejecutar migraciones después de crear tablas base
    await migrateDatabase();
  }).catch(err => console.error('Error creando tablas:', err));
}

let accessToken = null;
let tokenExpiry = null;

// MIDDLEWARE DE AUTENTICACIÓN
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Validar que el usuario existe en la base de datos
    const user = await findUserById(decoded.userId);
    if (!user) {
      return res.status(403).json({ error: 'Usuario no válido' });
    }
    
    // Validar que el email coincide
    if (user.email !== decoded.email) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Token inválido o expirado' });
  }
};

// HELPER FUNCTIONS PARA BASE DE DATOS
const findUserByEmail = async (email) => {
  if (!pool) return null;
  
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return result.rows[0];
};

const findUserById = async (id) => {
  if (!pool) return null;
  
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows[0];
};

const createUser = async (email, passwordHash) => {
  if (!pool) throw new Error('Base de datos no disponible');
  
  const userResult = await pool.query(
    'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
    [email, passwordHash]
  );
  const newUser = userResult.rows[0];
  
  // Crear perfil por defecto
  await pool.query(
    `INSERT INTO user_profiles (user_id, meal_names, meal_count, portion_distribution, personal_foods) 
     VALUES ($1, $2, $3, $4, $5)`,
    [
      newUser.id, 
      JSON.stringify(['Desayuno', 'Almuerzo', 'Cena']), 
      3, 
      JSON.stringify({}), 
      JSON.stringify({})
    ]
  );
  
  return newUser;
};

const getUserProfile = async (userId) => {
  if (!pool) return null;
  
  const result = await pool.query('SELECT * FROM user_profiles WHERE user_id = $1', [userId]);
  if (result.rows[0]) {
    return {
      ...result.rows[0],
      meal_names: result.rows[0].meal_names,
      portion_distribution: result.rows[0].portion_distribution,
      personal_foods: result.rows[0].personal_foods
    };
  }
  return null;
};

const updateUserProfile = async (userId, profileData) => {
  if (!pool) throw new Error('Base de datos no disponible');
  
  // Por ahora, solo guardar los campos que SÍ existen
  const result = await pool.query(
    `INSERT INTO user_profiles (
      user_id, meal_names, meal_count, 
      portion_distribution, personal_foods, updated_at
    ) 
    VALUES ($1, $2, $3, $4, $5, NOW()) 
    ON CONFLICT (user_id) 
    DO UPDATE SET 
      meal_names = $2,
      meal_count = $3,
      portion_distribution = $4,
      personal_foods = $5,
      updated_at = NOW()
    RETURNING *`,
    [
      userId,
      JSON.stringify(profileData.meal_names || []),
      profileData.meal_count || 3,
      JSON.stringify(profileData.portion_distribution || {}),
      JSON.stringify(profileData.personal_foods || {})
    ]
  );
  return result.rows[0];
};

const getConsumedFoods = async (userId, date) => {
  if (!pool) return null;
  
  const result = await pool.query(
    'SELECT * FROM consumed_foods WHERE user_id = $1 AND date = $2',
    [userId, date]
  );
  return result.rows[0];
};

const saveConsumedFoods = async (userId, date, consumedFoods) => {
  if (!pool) throw new Error('Base de datos no disponible');
  
  await pool.query(
    `INSERT INTO consumed_foods (user_id, date, consumed_foods) 
     VALUES ($1, $2, $3) 
     ON CONFLICT (user_id, date) 
     DO UPDATE SET 
       consumed_foods = $3,
       created_at = NOW()`,
    [userId, date, JSON.stringify(consumedFoods)]
  );
};

const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Configuración de email (usa variables de entorno)
const transporter = nodemailer.createTransport({
  service: 'gmail', // o tu servicio preferido
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // Usa App Password para Gmail
  }
});

// Función para generar código de 6 dígitos
const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Función para enviar email de verificación
const sendVerificationEmail = async (email, code) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Código de Verificación - Control de Porciones',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px;">
        <h2>Verificación de Cuenta</h2>
        <p>Tu código de verificación es:</p>
        <h1 style="color: #2563eb; font-size: 36px; letter-spacing: 5px;">${code}</h1>
        <p>Este código expirará en 15 minutos.</p>
        <p style="color: #666; font-size: 14px;">Si no solicitaste este código, ignora este mensaje.</p>
      </div>
    `
  };

  await transporter.sendMail(mailOptions);
};

// ENDPOINTS DE AUTENTICACIÓN
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }

    // VERIFICAR SI EL EMAIL ESTÁ EN LA WHITELIST
    /*const whitelistCheck = await pool.query(
      'SELECT * FROM email_whitelist WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    if (whitelistCheck.rows.length === 0) {
      return res.status(403).json({ 
        error: 'Este email no está autorizado para registrarse. Contacta al administrador.' 
      });
    }*/

    // Verificar si el usuario ya existe
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      if (existingUser.is_verified) {
        return res.status(409).json({ error: 'El email ya está registrado' });
      } else {
        // Si existe pero no está verificado, actualizar código
        const verificationCode = generateVerificationCode();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

        await pool.query(
          'UPDATE users SET verification_code = $1, verification_expires = $2 WHERE email = $3',
          [verificationCode, expiresAt, email]
        );

        await sendVerificationEmail(email, verificationCode);

        return res.status(200).json({
          message: 'Código de verificación reenviado',
          requiresVerification: true
        });
      }
    }

    // Generar código de verificación
    const verificationCode = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    // Hashear contraseña
    const passwordHash = await bcrypt.hash(password, 10);

    // Crear usuario no verificado
    const userResult = await pool.query(
      `INSERT INTO users (email, password_hash, is_verified, verification_code, verification_expires) 
       VALUES ($1, $2, FALSE, $3, $4) RETURNING *`,
      [email, passwordHash, verificationCode, expiresAt]
    );

    // Enviar email de verificación
    await sendVerificationEmail(email, verificationCode);

    res.status(201).json({
      message: 'Usuario creado. Revisa tu email para el código de verificación.',
      requiresVerification: true
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }

    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Verificar si el campo is_verified existe y si el usuario está verificado
    // Para usuarios antiguos, is_verified será null o true después de la migración
    if (user.is_verified === false) {
      try {
        // Solo intentar enviar código si el sistema de email está configurado
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
          const verificationCode = generateVerificationCode();
          const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

          await pool.query(
            'UPDATE users SET verification_code = $1, verification_expires = $2 WHERE id = $3',
            [verificationCode, expiresAt, user.id]
          );

          await sendVerificationEmail(email, verificationCode);

          return res.status(403).json({ 
            error: 'Email no verificado. Se ha enviado un nuevo código.',
            requiresVerification: true 
          });
        } else {
          // Si no hay sistema de email configurado, permitir login
          console.log('Sistema de verificación no configurado, permitiendo login');
        }
      } catch (emailError) {
        console.error('Error enviando email de verificación:', emailError);
        // Si falla el envío de email, permitir login para no bloquear usuarios
      }
    }

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        iat: Math.floor(Date.now() / 1000),
        jti: `${user.id}-${Date.now()}`
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
// Agregar email a whitelist (proteger con autenticación admin)
app.post('/api/admin/whitelist', authenticateToken, async (req, res) => {
  try {
    const { email, adminPassword } = req.body;
    
    // Verificar contraseña de admin
    if (adminPassword !== process.env.ADMIN_PASSWORD) {
      return res.status(403).json({ error: 'No autorizado' });
    }

    await pool.query(
      'INSERT INTO email_whitelist (email, added_by) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING',
      [email, req.user.email]
    );

    res.json({ message: 'Email agregado a la lista blanca' });
  } catch (error) {
    console.error('Error agregando a whitelist:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Obtener whitelist
app.get('/api/admin/whitelist', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM email_whitelist ORDER BY added_at DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Error obteniendo whitelist:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/auth/verify', authLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email y código son requeridos' });
    }

    const user = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const userData = user.rows[0];

    if (userData.is_verified) {
      return res.status(400).json({ error: 'El usuario ya está verificado' });
    }

    // Verificar código y expiración
    if (userData.verification_code !== code) {
      return res.status(400).json({ error: 'Código inválido' });
    }

    if (new Date() > new Date(userData.verification_expires)) {
      return res.status(400).json({ error: 'El código ha expirado' });
    }

    // Marcar como verificado
    await pool.query(
      'UPDATE users SET is_verified = TRUE, verification_code = NULL, verification_expires = NULL WHERE id = $1',
      [userData.id]
    );

    // Crear perfil por defecto
    await pool.query(
      `INSERT INTO user_profiles (user_id, meal_names, meal_count, portion_distribution, personal_foods) 
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id) DO NOTHING`,
      [
        userData.id,
        JSON.stringify(['Desayuno', 'Almuerzo', 'Cena']),
        3,
        JSON.stringify({}),
        JSON.stringify({})
      ]
    );

    // Generar token
    const token = jwt.sign(
      { 
        userId: userData.id, 
        email: userData.email,
        iat: Math.floor(Date.now() / 1000)
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Email verificado exitosamente',
      token,
      user: {
        id: userData.id,
        email: userData.email
      }
    });

  } catch (error) {
    console.error('Error en verificación:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await findUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({
      id: user.id,
      email: user.email,
      created_at: user.created_at
    });
  } catch (error) {
    console.error('Error en auth/me:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ENDPOINTS DE PERFIL DE USUARIO
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const profile = await getUserProfile(req.user.userId);
    
    if (!profile) {
      // Si no existe perfil, crear uno por defecto
      const defaultProfile = await updateUserProfile(req.user.userId, {
        meal_names: ['Desayuno', 'Almuerzo', 'Cena'],
        meal_count: 3,
        portion_distribution: {},
        personal_foods: {}
      });
      return res.json(defaultProfile);
    }

    res.json(profile);
  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { meal_names, meal_count, portion_distribution, personal_foods } = req.body;

    const updatedProfile = await updateUserProfile(req.user.userId, {
      meal_names,
      meal_count,
      portion_distribution,
      personal_foods
    });

    res.json({
      message: 'Perfil actualizado exitosamente',
      profile: updatedProfile
    });
  } catch (error) {
    console.error('Error actualizando perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ENDPOINTS DE ALIMENTOS CONSUMIDOS
app.get('/api/user/consumed-foods/:date', authenticateToken, async (req, res) => {
  try {
    const { date } = req.params;
    const consumedData = await getConsumedFoods(req.user.userId, date);

    res.json({
      date,
      consumed_foods: consumedData ? consumedData.consumed_foods : {}
    });
  } catch (error) {
    console.error('Error obteniendo alimentos consumidos:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/user/consumed-foods', authenticateToken, async (req, res) => {
  try {
    const { date, consumed_foods } = req.body;

    if (!date || !consumed_foods) {
      return res.status(400).json({ error: 'Fecha y alimentos consumidos son requeridos' });
    }

    await saveConsumedFoods(req.user.userId, date, consumed_foods);

    res.json({
      message: 'Alimentos consumidos guardados exitosamente',
      date,
      consumed_foods
    });
  } catch (error) {
    console.error('Error guardando alimentos consumidos:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// FUNCIÓN PARA OBTENER TOKEN DE FATSECRET
async function getToken() {
  if (accessToken && tokenExpiry && Date.now() < tokenExpiry) {
    return accessToken;
  }

  try {
    console.log('Obteniendo nuevo token de FatSecret...');
    
    if (!fetch) {
      const fetchModule = await import('node-fetch');
      fetch = fetchModule.default;
    }
    
    const authString = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    
    const response = await fetch('https://oauth.fatsecret.com/connect/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${authString}`
      },
      body: 'grant_type=client_credentials&scope=basic'
    });

    if (response.ok) {
      const data = await response.json();
      accessToken = data.access_token;
      tokenExpiry = Date.now() + (data.expires_in * 1000);
      console.log('Token de FatSecret obtenido exitosamente');
      return accessToken;
    } else {
      const errorText = await response.text();
      console.error('Error obteniendo token:', response.status, errorText);
    }
  } catch (error) {
    console.error('Error de red obteniendo token:', error.message);
  }
  return null;
}

// ENDPOINTS DE FATSECRET
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Backend funcionando correctamente',
    timestamp: new Date().toISOString(),
    fatsecret: accessToken ? 'Conectado' : 'Desconectado',
    auth: 'Habilitado',
    database: pool ? 'PostgreSQL' : 'No configurada'
  });
});

app.post('/api/search', async (req, res) => {
  try {
    const { query, maxResults = 20 } = req.body;
    
    if (!query || query.length < 2) {
      return res.status(400).json({ error: 'La consulta debe tener al menos 2 caracteres' });
    }

    console.log(`Buscando alimentos: "${query}"`);
    
    const token = await getToken();
    
    if (!token) {
      console.error('No se pudo obtener token de FatSecret');
      return res.status(500).json({ error: 'No se pudo conectar con FatSecret' });
    }

    if (!fetch) {
      const fetchModule = await import('node-fetch');
      fetch = fetchModule.default;
    }

    const params = new URLSearchParams({
      method: 'foods.search',
      search_expression: query,
      format: 'json',
      max_results: maxResults
    });

    const apiResponse = await fetch(`https://platform.fatsecret.com/rest/server.api?${params}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (apiResponse.ok) {
      const data = await apiResponse.json();
      
      let processedData = { foods: null };
      
      if (data.foods && data.foods.food) {
        const foods = Array.isArray(data.foods.food) ? data.foods.food : [data.foods.food];
        
        const processedFoods = foods.map(food => {
          let nutritionInfo = {};
          
          if (food.food_description) {
            const desc = food.food_description;
            
            const caloriesMatch = desc.match(/Calories:\s*(\d+(?:\.\d+)?)kcal/i);
            if (caloriesMatch) {
              nutritionInfo.calories = parseFloat(caloriesMatch[1]);
            }
            
            const fatMatch = desc.match(/Fat:\s*(\d+(?:\.\d+)?)g/i);
            if (fatMatch) {
              nutritionInfo.fat = parseFloat(fatMatch[1]);
            }
            
            const carbsMatch = desc.match(/Carbs:\s*(\d+(?:\.\d+)?)g/i);
            if (carbsMatch) {
              nutritionInfo.carbs = parseFloat(carbsMatch[1]);
            }
            
            const proteinMatch = desc.match(/Protein:\s*(\d+(?:\.\d+)?)g/i);
            if (proteinMatch) {
              nutritionInfo.protein = parseFloat(proteinMatch[1]);
            }
          }
          
          return {
            id: food.food_id,
            name: food.food_name,
            type: food.food_type || 'Generic',
            brand: food.brand_name || '',
            description: food.food_description || '',
            url: food.food_url || '',
            ...nutritionInfo
          };
        });
        
        processedData = {
          foods: {
            food: processedFoods,
            max_results: data.foods.max_results,
            page_number: data.foods.page_number,
            total_results: data.foods.total_results
          }
        };
        
        console.log(`Procesados ${processedFoods.length} alimentos con información nutricional`);
      }
      
      res.json(processedData);
    } else {
      const errorText = await apiResponse.text();
      console.error('Error de FatSecret API:', apiResponse.status, errorText);
      res.status(apiResponse.status).json({ 
        error: 'Error en FatSecret API', 
        details: errorText 
      });
    }

  } catch (error) {
    console.error('Error en búsqueda:', error.message);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`Servidor backend iniciado en puerto ${PORT}`);
  console.log(`API disponible en: http://localhost:${PORT}/api`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  
  if (!pool) {
    console.error('ADVERTENCIA: Base de datos no configurada - el sistema no funcionará');
  } else {
    console.log('Conectado a PostgreSQL');
  }
  
  // Probar conexión con FatSecret
  setTimeout(async () => {
    console.log('Probando conexión con FatSecret...');
    const token = await getToken();
    if (token) {
      console.log('Backend completamente listo con autenticación y FatSecret!');
    } else {
      console.log('Problemas con FatSecret API - revisa las credenciales');
    }
  }, 2000);
});