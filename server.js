const express = require('express');
const cors = require('cors');

// Importar fetch de la forma correcta
let fetch;
(async () => {
  fetch = (await import('node-fetch')).default;
})();

const app = express();

// Configurar CORS
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true
}));

app.use(express.json());

// ✅ CREDENCIALES ACTUALIZADAS DE FATSECRET
const CLIENT_ID = '45446b83c7094494bb5726aac82e59d2';      // Client ID
const CLIENT_SECRET = '2667e3f4cafe4d84896ee9cd3c9cdce9';   // Client Secret

let accessToken = null;
let tokenExpiry = null;

// Función para obtener token de FatSecret
async function getToken() {
  if (accessToken && tokenExpiry && Date.now() < tokenExpiry) {
    return accessToken;
  }

  try {
    console.log('🔐 Obteniendo nuevo token de FatSecret...');
    
    // Asegurar que fetch esté disponible
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
      console.log('✅ Token de FatSecret obtenido exitosamente');
      return accessToken;
    } else {
      const errorText = await response.text();
      console.error('❌ Error obteniendo token:', response.status, errorText);
    }
  } catch (error) {
    console.error('❌ Error de red obteniendo token:', error.message);
  }
  return null;
}

// Endpoint health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Backend funcionando correctamente',
    timestamp: new Date().toISOString(),
    fatsecret: accessToken ? 'Conectado' : 'Desconectado'
  });
});

// Endpoint para buscar alimentos - MEJORADO
app.post('/api/search', async (req, res) => {
  try {
    const { query, maxResults = 20 } = req.body;
    
    if (!query || query.length < 2) {
      return res.status(400).json({ error: 'La consulta debe tener al menos 2 caracteres' });
    }

    console.log(`🔍 Buscando alimentos: "${query}"`);
    
    const token = await getToken();
    
    if (!token) {
      console.error('❌ No se pudo obtener token de FatSecret');
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

    console.log(`📡 URL completa: https://platform.fatsecret.com/rest/server.api?${params}`);

    const apiResponse = await fetch(`https://platform.fatsecret.com/rest/server.api?${params}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    console.log(`📡 Status de respuesta: ${apiResponse.status}`);

    if (apiResponse.ok) {
      const data = await apiResponse.json();
      console.log('📊 Respuesta completa de FatSecret:', JSON.stringify(data, null, 2));
      
      // MEJORAR MANEJO DE DIFERENTES TIPOS DE RESPUESTA
      let processedData = { foods: null };
      
      if (data.foods && data.foods.food) {
        // Si hay resultados
        const foods = Array.isArray(data.foods.food) ? data.foods.food : [data.foods.food];
        
        // Procesar cada alimento para extraer información nutricional de food_description
        const processedFoods = foods.map(food => {
          let nutritionInfo = {};
          
          // Extraer información nutricional de food_description
          if (food.food_description) {
            const desc = food.food_description;
            
            // Extraer calorías: "Calories: 300kcal"
            const caloriesMatch = desc.match(/Calories:\s*(\d+(?:\.\d+)?)kcal/i);
            if (caloriesMatch) {
              nutritionInfo.calories = parseFloat(caloriesMatch[1]);
            }
            
            // Extraer grasas: "Fat: 13.00g"
            const fatMatch = desc.match(/Fat:\s*(\d+(?:\.\d+)?)g/i);
            if (fatMatch) {
              nutritionInfo.fat = parseFloat(fatMatch[1]);
            }
            
            // Extraer carbohidratos: "Carbs: 32.00g"
            const carbsMatch = desc.match(/Carbs:\s*(\d+(?:\.\d+)?)g/i);
            if (carbsMatch) {
              nutritionInfo.carbs = parseFloat(carbsMatch[1]);
            }
            
            // Extraer proteínas: "Protein: 15.00g"
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
            // Añadir información nutricional extraída
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
        
        console.log(`✅ Procesados ${processedFoods.length} alimentos con información nutricional`);
      } else {
        console.log('❌ No se encontraron alimentos en la respuesta');
      }
      
      res.json(processedData);
    } else {
      const errorText = await apiResponse.text();
      console.error('❌ Error de FatSecret API:', apiResponse.status, errorText);
      
      // Intentar parsear el error como JSON
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
    console.error('❌ Error en búsqueda:', error.message);
    res.status(500).json({ error: 'Error interno del servidor', details: error.message });
  }
});

// Endpoint para obtener detalles de un alimento - MEJORADO
app.post('/api/food/:id', async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`📋 Obteniendo detalles del alimento ID: ${id}`);
    
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
      console.log('✅ Detalles nutricionales completos obtenidos');
      console.log('📊 Detalles:', JSON.stringify(data, null, 2));
      res.json(data);
    } else {
      const errorText = await apiResponse.text();
      console.error('❌ Error obteniendo detalles:', apiResponse.status, errorText);
      res.status(apiResponse.status).json({ error: 'Error obteniendo detalles del alimento' });
    }

  } catch (error) {
    console.error('❌ Error obteniendo detalles:', error.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Endpoint de prueba para hacer una búsqueda específica
app.get('/api/test-search/:query', async (req, res) => {
  try {
    const query = req.params.query;
    console.log(`🧪 PRUEBA: Buscando "${query}"`);
    
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
    console.log('🧪 RESULTADO DE PRUEBA:', JSON.stringify(data, null, 2));
    
    res.json({
      status: apiResponse.status,
      data: data
    });

  } catch (error) {
    console.error('🧪 ERROR EN PRUEBA:', error);
    res.status(500).json({ error: error.message });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  console.log(`🚀 Servidor backend iniciado en puerto ${PORT}`);
  console.log(`📡 API disponible en: http://localhost:${PORT}/api`);
  console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🧪 Test search: http://localhost:${PORT}/api/test-search/chicken`);
  console.log('');
  
  // Probar conexión con FatSecret
  setTimeout(async () => {
    console.log('🧪 Probando conexión con FatSecret...');
    const token = await getToken();
    if (token) {
      console.log('🎉 ¡Backend completamente listo!');
      console.log('🔍 Prueba abrir: http://localhost:3001/api/test-search/chicken');
    } else {
      console.log('⚠️  Problemas con FatSecret API - revisa las credenciales');
    }
  }, 2000);
});