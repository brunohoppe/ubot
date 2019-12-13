// -Wall -Wextra -lcurl -lssl -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "jsmn.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <time.h>
#include <sys/timeb.h>
#include<signal.h>
char *queryApiKey = "apikey=";
char *queryNonce = "nonce=";

int signalPoint = 1;
struct MemoryStruct {
  char *memory;
  size_t size;
};
struct Exchange {
  int id;
  char *url;
  char *apiKey;
  char *apiSecret;
  double minTradeSize;
};
void handle_sigint(int sig)
{
    printf("Caught signal %d\n", sig);
    signalPoint = 0;
}
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}
long int *getTimeStamp() {
  long int *timeStamp = malloc( sizeof (long int));
  time_t a = time(NULL);
  struct timeb tmb;
  struct tm tm = *localtime(&a);
  long int ag = tm.tm_year + 1900 + tm.tm_mon + 1 + tm.tm_mday;
  ftime(&tmb);
  *timeStamp = tmb.time * 1000 + tmb.millitm + ag;
  // printf("%ld\n", *timeStamp);
  // printf("tmb.time     = %ld (seconds)\n", tmb.time * 1000 + tmb.millitm + ag);
  // printf("tmb.millitm  = %d (mlliseconds)\n", tmb.millitm);
  return timeStamp;
}
char *get(char *url, char *headers) {
  struct MemoryStruct chunk;
  chunk.memory = malloc(1);
  chunk.size = 0;
  CURL *curl;
  CURLcode res;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();
  struct curl_slist *list = NULL;
  if(curl) {
    if(headers != NULL) {
      list = curl_slist_append(list, headers);
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    curl_easy_cleanup(curl);
    curl_slist_free_all(list);
    curl_global_cleanup();
  }
  return chunk.memory;
}
char *post(char *url, char *headers) {
  struct MemoryStruct chunk;
  chunk.memory = malloc(1);
  chunk.size = 0;
  CURL *curl;
  CURLcode res;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();
  struct curl_slist *list = NULL;
  if(curl) {
    list = curl_slist_append(list, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    curl_easy_cleanup(curl);
    curl_slist_free_all(list);
    curl_global_cleanup();
  }
  return chunk.memory;
}
char *getProp(char *json, char *prop) {
  int r;
  int i;
  char *subbuff = NULL;
  int begin, end;
  jsmn_parser p;
  jsmntok_t t[1000]; /* We expect no more than 1000 JSON tokens */
  jsmn_init(&p);
  r = jsmn_parse(&p, json, strlen(json), t, 1000);
  if (r < 0) {
    printf("Failed to parse JSON: %d\n", r);
    return NULL;
  }
  for (i = 1; i < r; i++) {
    if (jsoneq(json, &t[i], prop) == 0) {
      // printf("Prop: %.*s\n", t[i + 1].end - t[i + 1].start,
      //        json + t[i + 1].start);
      begin = t[i + 1].start;
      end = t[i + 1].end;
      i++;
    }
  }
  if (end > 0) {
    subbuff = malloc(end - begin);
    memcpy( subbuff, &json[begin], end - begin);
    subbuff[end - begin] = '\0';
  }
  return subbuff;
}
char *getUri(char *url, long int *nonce) {
  char uriArr[256];
  char *uri = malloc(256 * sizeof (char));
  snprintf(uriArr, sizeof uriArr, "%s%s%s&%s%ld", url, queryApiKey, apikeyBleu, queryNonce, *nonce);
  memcpy(uri, uriArr, sizeof uriArr);
  puts(uri);
  return uri;
}
char *getApiSign(char *uri) {
  static char mdString[2000];
  unsigned char* digest;
  digest = HMAC(EVP_sha512(), apiSecretBleu, strlen(apiSecretBleu), (unsigned char*)uri, strlen(uri), NULL, NULL);
  for(int i = 0; i < 64; i++)
      sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
  return mdString;
}
char *callPrivateApi(char *exchangeUrl) {
  char headers[256];
  long int *timeStamp = getTimeStamp();
  char *uri = getUri(exchangeUrl, timeStamp);
  char *apisign = getApiSign(uri);
  char *response = NULL;
  snprintf(headers, sizeof headers, "%s:%s", "apisign", apisign);
  response = post(uri, headers);
  free(uri);
  free(timeStamp);
  return response;
}
char *callPublicApi(char *exchangeUrl) {
  return get(exchangeUrl, NULL);
}
char *getBalances(char* exchangeUrl) {
  char url[128];
  char *balanceUrl = "/private/getbalances?";
  snprintf(url, sizeof url, "%s%s", exchangeUrl, balanceUrl);
  return callPrivateApi(url);
}
double getResponseProp(char *markets, char *responseProp) {
  char *result = getProp(markets, responseProp);
  double ret = 0.0;
  if(result != NULL) {
    char *a;
    ret = strtod(result, &a);
    free(result);

  }
  return ret;
}
double getMarkets(char *exchangeUrl) {
  char url[128];
  char *marketsUrl = "/public/getmarkets";
  snprintf(url, sizeof url, "%s%s", exchangeUrl, marketsUrl);
  char *response = callPublicApi(url);
  double minTradeSize = getResponseProp(response, "MinTradeSize");
  free(response);
  return minTradeSize;
}
char *getOrderBook(char* exchangeUrl, char* market, char* type) {
  char url[128];
  char *orderBookUrl = "/public/getorderbook?";
  snprintf(url, sizeof url, "%s%smarket=%s&type=%s&depth=1", exchangeUrl, orderBookUrl, market, type);
  return callPublicApi(url);
}
int makeDirectTransfer(struct Exchange exchangeFrom, struct Exchange exchangeTo, char *asset, double quantity) {
  char url[128];
  char *directTransferUrl = "/private/directtransfer?";
  snprintf(url, sizeof url, "%s%sasset=%s&quantity=%4.8f&exchangeto=%d", exchangeFrom.url, directTransferUrl, asset, quantity, exchangeTo.id);
  char *response = callPrivateApi(url);
  puts(response);
  return 0;
}

double computeActionValue(char *url, char *market, char *type) {
  double valueTo = 0;

  char *response = getOrderBook(url, market, type);
  double orderQuantity = getResponseProp(response, "Quantity");
  double orderRate = getResponseProp(response, "Rate");
  char *op = NULL;
  if(strcmp(type, "BUY") == 0) {
    op = "SELL";
    valueTo = orderQuantity * 0.9975 * orderRate;
  }else {
    op = "BUY";
    valueTo = orderQuantity * 1.0025 * orderRate;
  }
  // printf("Qtd: %4.9f\n", orderQuantity);
  // printf("Rate: %4.9f\n", orderRate);
  // printf("%s: %4.9f\n", op, valueTo);
  free(response);
  return valueTo;
}
void goThroughExchanges(struct Exchange buyPlace, struct Exchange sellPlace , char *market) {

    double valueToPay = computeActionValue(buyPlace.url, market, "SELL");
    double valueToReceive = 0;
    if(valueToPay > buyPlace.minTradeSize) {
      valueToReceive = computeActionValue(sellPlace.url, market, "BUY");
      printf("-------------------------------\n");
      printf("Value to Pay: %4.8f\n", valueToPay);
      printf("Value to Receive: %4.8f\n", valueToReceive);
      printf("-------------------------------\n");
      if(valueToReceive > sellPlace.minTradeSize) {
        printf("\nValue: %4.8f\n\n", valueToReceive - valueToPay);
      } else {
        printf("-------------------------------\n");
        printf("mintrade reached\n");
      }
    } else {
      printf("mintrade reached\n");
    }
}
void setExchange(int id, char *url, char *apiKey, char *apiSecret, double minTradeSize, struct Exchange *exchange) {
  exchange->id = id;
  exchange->url = url;
  exchange->apiKey = apiKey;
  exchange->apiSecret = apiSecret;
  exchange->minTradeSize = minTradeSize;
}
int main(void)
{
  struct Exchange bleuTrade;
  struct Exchange exc;
  double minTradeSizeBleu = getMarkets(bleuTradeUrl);
  double minTradeSizeExc = getMarkets(excUrl);
  setExchange(1, bleuTradeUrl, apikeyBleu, apiSecretBleu, minTradeSizeBleu, &bleuTrade);
  setExchange(2, excUrl, apikeyExc, apiSecretExc, minTradeSizeExc, &exc);
  makeDirectTransfer(exc, bleuTrade, "UT_BTC", 0.00006946);
  // signal(2, handle_sigint);
  // while (signalPoint == 1)
  // {
  //   goThroughExchanges(bleuTrade, exc, "ETH_BTC");
  // }
  printf("\nBye!\n");
  return 0;
}
