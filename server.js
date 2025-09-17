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
  `).then(() => console.log('✅ Tablas creadas/verificadas en PostgreSQL'))
    .catch(err => console.error('Error creando tablas:', err));
} else {
  console.error('⚠️ DATABASE_URL no configurada - el sistema no funcionará correctamente');
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
  
  const result = await pool.query(
    `INSERT INTO user_profiles (
      user_id, first_name, last_name, birth_date, 
      current_weight, weight_history, meal_names, 
      meal_count, portion_distribution, personal_foods, updated_at
    ) 
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) 
    ON CONFLICT (user_id) 
    DO UPDATE SET 
      first_name = $2,
      last_name = $3,
      birth_date = $4,
      current_weight = $5,
      weight_history = $6,
      meal_names = $7,
      meal_count = $8,
      portion_distribution = $9,
      personal_foods = $10,
      updated_at = NOW()
    RETURNING *`,
    [
      userId,
      profileData.first_name || null,
      profileData.last_name || null,
      profileData.birth_date || null,
      profileData.current_weight || null,
      JSON.stringify(profileData.weight_history || []),
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

    // Verificar si el usuario ya existe
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }

    // Hashear contraseña
    const passwordHash = await bcrypt.hash(password, 10);

    // Crear usuario
    const newUser = await createUser(email, passwordHash);

    // Generar token
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({
      message: 'Usuario creado exitosamente',
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        created_at: newUser.created_at
      }
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

    // Buscar usuario
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Verificar contraseña
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Generar token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
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



// Iniciar servidor
const token = jwt.sign(
  { 
    userId: newUser.id, 
    email: newUser.email,
    iat: Math.floor(Date.now() / 1000), // Agregar timestamp explícito
    jti: `${newUser.id}-${Date.now()}` // JWT ID único
  },
  JWT_SECRET,
  { expiresIn: '30d' }
);