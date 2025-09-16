const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// Importar fetch de la forma correcta
let fetch;
(async () => {
  fetch = (await import('node-fetch')).default;
})();

const app = express();

// Middleware para parsear JSON
app.use(express.json());

// Rate limiting para auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // máximo 5 intentos por IP
  message: { error: 'Demasiados intentos, intenta de nuevo más tarde' }
});

// Configurar CORS
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  process.env.FRONTEND_ORIGIN, // tu dominio principal
  'https://portion-tracker-frontend.vercel.app', // preview actual
  'https://portion-tracker*.vercel.app' // para permitir todos los previews (menos seguro)
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // Postman/CLI
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// CREDENCIALES Y CONFIGURACIÓN
const CLIENT_ID = process.env.FATSECRET_CLIENT_ID;
const CLIENT_SECRET = process.env.FATSECRET_CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Faltan FATSECRET_CLIENT_ID o FATSECRET_CLIENT_SECRET');
}

if (!JWT_SECRET || JWT_SECRET === 'tu-super-secreto-jwt-cambiar-en-produccion') {
  console.warn('ADVERTENCIA: Define JWT_SECRET en las variables de entorno');
}

// SIMULACIÓN DE BASE DE DATOS EN MEMORIA (para desarrollo)
// En producción deberías usar PostgreSQL, MySQL, etc.
let database = {
  users: [
    // Ejemplo: { id: 1, email: 'test@test.com', password_hash: 'hash', created_at: '2024-01-01' }
  ],
  user_profiles: [
    // Ejemplo: { user_id: 1, meal_names: [...], meal_count: 3, portion_distribution: {}, personal_foods: {} }
  ],
  consumed_foods: [
    // Ejemplo: { id: 1, user_id: 1, date: '2024-01-01', consumed_foods: {} }
  ]
};

// Si tienes DATABASE_URL, aquí conectarías a la base de datos real
if (DATABASE_URL) {
  console.log('DATABASE_URL detectada - conectar a base de datos real aquí');
  // const { Pool } = require('pg');
  // const pool = new Pool({ connectionString: DATABASE_URL });
}

let accessToken = null;
let tokenExpiry = null;

// MIDDLEWARE DE AUTENTICACIÓN
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// HELPER FUNCTIONS PARA BASE DE DATOS SIMULADA
const findUserByEmail = (email) => {
  return database.users.find(user => user.email === email);
};

const findUserById = (id) => {
  return database.users.find(user => user.id === id);
};

const createUser = (email, passwordHash) => {
  const newUser = {
    id: database.users.length + 1,
    email,
    password_hash: passwordHash,
    created_at: new Date().toISOString()
  };
  database.users.push(newUser);
  
  // Crear perfil por defecto
  const defaultProfile = {
    user_id: newUser.id,
    meal_names: ['Desayuno', 'Almuerzo', 'Cena'],
    meal_count: 3,
    portion_distribution: {},
    personal_foods: {},
    updated_at: new Date().toISOString()
  };
  database.user_profiles.push(defaultProfile);
  
  return newUser;
};

const getUserProfile = (userId) => {
  return database.user_profiles.find(profile => profile.user_id === userId);
};

const updateUserProfile = (userId, profileData) => {
  const index = database.user_profiles.findIndex(profile => profile.user_id === userId);
  if (index !== -1) {
    database.user_profiles[index] = {
      ...database.user_profiles[index],
      ...profileData,
      updated_at: new Date().toISOString()
    };
    return database.user_profiles[index];
  }
  return null;
};

const getConsumedFoods = (userId, date) => {
  return database.consumed_foods.find(cf => cf.user_id === userId && cf.date === date);
};

const saveConsumedFoods = (userId, date, consumedFoods) => {
  const index = database.consumed_foods.findIndex(cf => cf.user_id === userId && cf.date === date);
  
  if (index !== -1) {
    database.consumed_foods[index] = {
      ...database.consumed_foods[index],
      consumed_foods: consumedFoods,
      updated_at: new Date().toISOString()
    };
  } else {
    database.consumed_foods.push({
      id: database.consumed_foods.length + 1,
      user_id: userId,
      date,
      consumed_foods: consumedFoods,
      created_at: new Date().toISOString()
    });
  }
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
    if (findUserByEmail(email)) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }

    // Hashear contraseña
    const passwordHash = await bcrypt.hash(password, 10);

    // Crear usuario
    const newUser = createUser(email, passwordHash);

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
    const user = findUserByEmail(email);
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

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = findUserById(req.user.userId);
  if (!user) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  res.json({
    id: user.id,
    email: user.email,
    created_at: user.created_at
  });
});

// ENDPOINTS DE PERFIL DE USUARIO
app.get('/api/user/profile', authenticateToken, (req, res) => {
  try {
    const profile = getUserProfile(req.user.userId);
    
    if (!profile) {
      return res.status(404).json({ error: 'Perfil no encontrado' });
    }

    res.json(profile);
  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.put('/api/user/profile', authenticateToken, (req, res) => {
  try {
    const { meal_names, meal_count, portion_distribution, personal_foods } = req.body;

    const updatedProfile = updateUserProfile(req.user.userId, {
      meal_names,
      meal_count,
      portion_distribution,
      personal_foods
    });

    if (!updatedProfile) {
      return res.status(404).json({ error: 'Perfil no encontrado' });
    }

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
app.get('/api/user/consumed-foods/:date', authenticateToken, (req, res) => {
  try {
    const { date } = req.params;
    const consumedData = getConsumedFoods(req.user.userId, date);

    res.json({
      date,
      consumed_foods: consumedData ? consumedData.consumed_foods : {}
    });
  } catch (error) {
    console.error('Error obteniendo alimentos consumidos:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/user/consumed-foods', authenticateToken, (req, res) => {
  try {
    const { date, consumed_foods } = req.body;

    if (!date || !consumed_foods) {
      return res.status(400).json({ error: 'Fecha y alimentos consumidos son requeridos' });
    }

    saveConsumedFoods(req.user.userId, date, consumed_foods);

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

// FUNCIÓN PARA OBTENER TOKEN DE FATSECRET (sin cambios)
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

// ENDPOINTS EXISTENTES DE FATSECRET (sin cambios)
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Backend funcionando correctamente',
    timestamp: new Date().toISOString(),
    fatsecret: accessToken ? 'Conectado' : 'Desconectado',
    auth: 'Habilitado',
    database: DATABASE_URL ? 'PostgreSQL' : 'Memoria (desarrollo)'
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
      
      try {
        const errorJson = JSON.parse(errorText);
        res.status(apiResponse.status).json({ 
          error: 'Error en FatSecret API', 
          details: errorJson 
        });
      } catch {
        res.status(apiResponse.status).json({ 
          error: 'Error en FatSecret API', 
          details: errorText 
        });
      }
    }

  } catch (error) {
    console.error('Error en búsqueda:', error.message);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

app.post('/api/food/:id', async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Obteniendo detalles del alimento ID: ${id}`);
    
    const token = await getToken();

    if (!token) {
      return res.status(500).json({ error: 'No se pudo conectar con FatSecret' });
    }

    if (!fetch) {
      const fetchModule = await import('node-fetch');
      fetch = fetchModule.default;
    }

    const params = new URLSearchParams({
      method: 'food.get',
      food_id: id,
      format: 'json'
    });

    const apiResponse = await fetch(`https://platform.fatsecret.com/rest/server.api?${params}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (apiResponse.ok) {
      const data = await apiResponse.json();
      console.log('Detalles nutricionales completos obtenidos');
      res.json(data);
    } else {
      const errorText = await apiResponse.text();
      console.error('Error obteniendo detalles:', apiResponse.status, errorText);
      res.status(apiResponse.status).json({ error: 'Error obteniendo detalles del alimento' });
    }

  } catch (error) {
    console.error('Error obteniendo detalles:', error.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/test-search/:query', async (req, res) => {
  try {
    const query = req.params.query;
    console.log(`PRUEBA: Buscando "${query}"`);
    
    const token = await getToken();
    if (!token) {
      return res.status(500).json({ error: 'No hay token disponible' });
    }

    if (!fetch) {
      const fetchModule = await import('node-fetch');
      fetch = fetchModule.default;
    }

    const params = new URLSearchParams({
      method: 'foods.search',
      search_expression: query,
      format: 'json',
      max_results: 5
    });

    const apiResponse = await fetch(`https://platform.fatsecret.com/rest/server.api?${params}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    const data = await apiResponse.json();
    console.log('RESULTADO DE PRUEBA:', JSON.stringify(data, null, 2));
    
    res.json({
      status: apiResponse.status,
      data: data
    });

  } catch (error) {
    console.error('ERROR EN PRUEBA:', error);
    res.status(500).json({ error: error.message });
  }
});

// ENDPOINT PARA VER DATOS DE DESARROLLO (solo en desarrollo)
if (!DATABASE_URL) {
  app.get('/api/debug/database', (req, res) => {
    res.json({
      message: 'Base de datos en memoria (solo desarrollo)',
      data: {
        users_count: database.users.length,
        profiles_count: database.user_profiles.length,
        consumed_foods_count: database.consumed_foods.length,
        users: database.users.map(u => ({ id: u.id, email: u.email, created_at: u.created_at }))
      }
    });
  });
}

// Iniciar servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  console.log(`Servidor backend iniciado en puerto ${PORT}`);
  console.log(`API disponible en: http://localhost:${PORT}/api`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  console.log(`Test search: http://localhost:${PORT}/api/test-search/chicken`);
  
  if (!DATABASE_URL) {
    console.log(`Debug database: http://localhost:${PORT}/api/debug/database`);
    console.log('MODO DESARROLLO: Usando base de datos en memoria');
  }
  
  console.log('ENDPOINTS DE AUTENTICACIÓN:');
  console.log('- POST /api/auth/register');
  console.log('- POST /api/auth/login');
  console.log('- GET /api/auth/me');
  console.log('- GET /api/user/profile');
  console.log('- PUT /api/user/profile');
  console.log('- GET /api/user/consumed-foods/:date');
  console.log('- POST /api/user/consumed-foods');
  console.log('');
  
  // Probar conexión con FatSecret
  setTimeout(async () => {
    console.log('Probando conexión con FatSecret...');
    const token = await getToken();
    if (token) {
      console.log('Backend completamente listo con autenticación!');
    } else {
      console.log('Problemas con FatSecret API - revisa las credenciales');
    }
  }, 2000);
});