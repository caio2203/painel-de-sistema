# Dockerfile para o projeto paniel-de-sistema
# Baseado em Node.js LTS
FROM node:18-slim

# Diretório de trabalho dentro do container
WORKDIR /app

# Copia apenas arquivos essenciais primeiro para otimizar cache
COPY back/package*.json ./back/

# Instala dependências do backend
RUN cd back && npm install --production && cd ..

# Copia todo o restante do projeto para dentro do container
COPY . .

# Expõe a porta usada pelo backend (ajuste se necessário)
EXPOSE 3000

# Comando para iniciar o backend
CMD ["node", "back/index.js"]

# Dicas:
# - O arquivo painel-de-sistema-bd.db será copiado junto e estará disponível para o Node.js.
# - Se quiser persistir o banco fora do container, use volumes ao rodar o container.
# - Para servir arquivos estáticos (HTML), adicione lógica no back/index.js para servir as pastas Admin, Medico, Recepcao, Tv. 