# HashCalc

Demonstração de benchmark de cálculo de hash em arquivos usando JavaScript no navegador.

## Como usar

1. Abra o arquivo `src/index.html` em seu navegador.
2. Faça upload de um arquivo.
3. O sistema irá calcular vários hashes (MD5, SHA-1, SHA-256, SHA-512, SHA-3-512) usando diferentes bibliotecas e medir o tempo de execução de cada um.
4. Os resultados são armazenados no localStorage e exibidos em um gráfico de barras.

## Bibliotecas utilizadas
- [SparkMD5](https://github.com/satazor/js-spark-md5) para MD5
- [jsSHA](https://github.com/Caligatio/jsSHA) para SHA-3
- WebCrypto API para SHA-1, SHA-256, SHA-512
- [Chart.js](https://www.chartjs.org/) para gráficos

## Observações
- O cálculo de ciclos de CPU não é possível diretamente via JavaScript no navegador, mas o tempo de execução é um bom indicativo de performance relativa.
- Os resultados anteriores ficam salvos no localStorage do navegador.