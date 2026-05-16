import fs from "node:fs";
import path from "node:path";
import { extractUrlMlFeatures, URL_ML_FEATURES } from "./url-ml-features";

export type LexicalUrlMlModel = {
  modelType: "logistic_regression";
  version: number;
  trainedAt: string;
  positiveSource: string;
  negativeSource: string;
  positiveCount: number;
  negativeCount: number;
  featureNames: string[];
  weights: number[];
  bias: number;
  threshold: number;
  metrics?: Record<string, number>;
};

export type CharPositionUrlMlModel = {
  modelType: "char_position_logistic";
  version: number;
  trainedAt: string;
  source: string;
  labelMeaning: {
    "0": "legitimate";
    "1": "phishing";
  };
  maxLength: number;
  padToken: string;
  charToInt: Record<string, number>;
  weights: number[][];
  bias: number;
  threshold: number;
  metrics?: Record<string, number>;
};

export type HashedNgramUrlMlModel = {
  modelType: "hashed_ngram_logistic";
  version: number;
  trainedAt: string;
  source: string;
  labelMeaning: {
    "0": "legitimate";
    "1": "phishing";
  };
  nFeatures: number;
  ngramMin: number;
  ngramMax: number;
  lowercase: boolean;
  norm: "l2";
  weights: number[];
  bias: number;
  threshold: number;
  metrics?: Record<string, number>;
};

export type UrlMlModel = LexicalUrlMlModel | CharPositionUrlMlModel | HashedNgramUrlMlModel;

export type UrlMlPrediction = {
  probability: number;
  threshold: number;
  predictedPhishing: boolean;
  topFeatures: Array<{ name: string; contribution: number }>;
  modelPath: string;
  trainedAt: string;
};

export function loadUrlMlModel(modelPath = process.env.URL_AI_MODEL_PATH ?? path.resolve(process.cwd(), "models", "url-phishing-model.json")): UrlMlModel | null {
  if (!fs.existsSync(modelPath)) {
    return null;
  }
  const model = JSON.parse(fs.readFileSync(modelPath, "utf8")) as UrlMlModel;
  if (model.modelType === "logistic_regression") {
    if (!Array.isArray(model.featureNames) || !Array.isArray(model.weights) || model.featureNames.length !== URL_ML_FEATURES.length) {
      throw new Error(`Invalid lexical URL AI model at ${modelPath}`);
    }
    return model;
  }
  if (model.modelType === "char_position_logistic") {
    if (!model.charToInt || !Array.isArray(model.weights) || model.weights.length !== model.maxLength) {
      throw new Error(`Invalid character-position URL AI model at ${modelPath}`);
    }
    return model;
  }
  if (model.modelType === "hashed_ngram_logistic") {
    if (!Array.isArray(model.weights) || model.weights.length !== model.nFeatures) {
      throw new Error(`Invalid hashed n-gram URL AI model at ${modelPath}`);
    }
    return model;
  }
  {
    throw new Error(`Invalid URL AI model at ${modelPath}`);
  }
}

export function predictUrlPhishing(rawUrl: string, model: UrlMlModel, modelPath = process.env.URL_AI_MODEL_PATH ?? path.resolve(process.cwd(), "models", "url-phishing-model.json")): UrlMlPrediction | null {
  if (model.modelType === "char_position_logistic") {
    return predictCharPositionUrlPhishing(rawUrl, model, modelPath);
  }
  if (model.modelType === "hashed_ngram_logistic") {
    return predictHashedNgramUrlPhishing(rawUrl, model, modelPath);
  }
  return predictLexicalUrlPhishing(rawUrl, model, modelPath);
}

function predictLexicalUrlPhishing(rawUrl: string, model: LexicalUrlMlModel, modelPath: string): UrlMlPrediction | null {
  const vector = extractUrlMlFeatures(rawUrl);
  if (!vector) return null;
  let logit = model.bias;
  const contributions = vector.values.map((value, index) => {
    const contribution = value * model.weights[index];
    logit += contribution;
    return {
      name: model.featureNames[index],
      contribution
    };
  });
  const probability = sigmoid(logit);
  return {
    probability,
    threshold: model.threshold,
    predictedPhishing: probability >= model.threshold,
    topFeatures: contributions
      .filter((feature) => feature.contribution > 0)
      .sort((a, b) => b.contribution - a.contribution)
      .slice(0, 5),
    modelPath,
    trainedAt: model.trainedAt
  };
}

function predictCharPositionUrlPhishing(rawUrl: string, model: CharPositionUrlMlModel, modelPath: string): UrlMlPrediction {
  const padIndex = model.charToInt[model.padToken] ?? 0;
  const normalized = normalizeInput(rawUrl);
  let logit = model.bias;
  const contributions: Array<{ name: string; contribution: number }> = [];

  for (let position = 0; position < model.maxLength; position += 1) {
    const char = normalized[position] ?? model.padToken;
    const index = model.charToInt[char] ?? padIndex;
    const contribution = model.weights[position]?.[index] ?? 0;
    logit += contribution;
    if (contribution > 0.02 && char !== model.padToken) {
      contributions.push({
        name: `char_position_${position}='${safeFeatureChar(char)}'`,
        contribution
      });
    }
  }

  const probability = sigmoid(logit);
  return {
    probability,
    threshold: model.threshold,
    predictedPhishing: probability >= model.threshold,
    topFeatures: contributions.sort((a, b) => b.contribution - a.contribution).slice(0, 5),
    modelPath,
    trainedAt: model.trainedAt
  };
}

function predictHashedNgramUrlPhishing(rawUrl: string, model: HashedNgramUrlMlModel, modelPath: string): UrlMlPrediction {
  const normalized = model.lowercase ? normalizeInput(rawUrl).toLowerCase() : normalizeInput(rawUrl);
  const counts = new Map<number, { count: number; token: string }>();
  for (let size = model.ngramMin; size <= model.ngramMax; size += 1) {
    for (let index = 0; index <= normalized.length - size; index += 1) {
      const token = normalized.slice(index, index + size);
      const hash = Math.abs(murmurhash3Utf8(token, 0)) % model.nFeatures;
      const previous = counts.get(hash);
      counts.set(hash, { count: (previous?.count ?? 0) + 1, token: previous?.token ?? token });
    }
  }

  let norm = 0;
  for (const item of counts.values()) norm += item.count * item.count;
  norm = model.norm === "l2" && norm > 0 ? Math.sqrt(norm) : 1;

  let logit = model.bias;
  const contributions: Array<{ name: string; contribution: number }> = [];
  for (const [hash, item] of counts) {
    const value = item.count / norm;
    const contribution = value * (model.weights[hash] ?? 0);
    logit += contribution;
    if (contribution > 0.015) {
      contributions.push({ name: `ngram='${safeFeatureChar(item.token)}'`, contribution });
    }
  }

  const probability = sigmoid(logit);
  return {
    probability,
    threshold: model.threshold,
    predictedPhishing: probability >= model.threshold,
    topFeatures: contributions.sort((a, b) => b.contribution - a.contribution).slice(0, 5),
    modelPath,
    trainedAt: model.trainedAt
  };
}

function normalizeInput(value: string): string {
  try {
    return decodeURIComponent(value.trim());
  } catch {
    return value.trim();
  }
}

function safeFeatureChar(value: string): string {
  if (value === "\n") return "\\n";
  if (value === "\r") return "\\r";
  if (value === "\t") return "\\t";
  return value.replace(/'/g, "\\'");
}

function murmurhash3Utf8(value: string, seed: number): number {
  const bytes = new TextEncoder().encode(value);
  let h1 = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const roundedEnd = bytes.length & ~3;

  for (let i = 0; i < roundedEnd; i += 4) {
    let k1 = (bytes[i] & 0xff) | ((bytes[i + 1] & 0xff) << 8) | ((bytes[i + 2] & 0xff) << 16) | ((bytes[i + 3] & 0xff) << 24);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);

    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) >>> 0;
  }

  let k1 = 0;
  switch (bytes.length & 3) {
    case 3:
      k1 ^= (bytes[roundedEnd + 2] & 0xff) << 16;
    // falls through
    case 2:
      k1 ^= (bytes[roundedEnd + 1] & 0xff) << 8;
    // falls through
    case 1:
      k1 ^= bytes[roundedEnd] & 0xff;
      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
  }

  h1 ^= bytes.length;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0;
}

function sigmoid(value: number): number {
  if (value < -35) return 0;
  if (value > 35) return 1;
  return 1 / (1 + Math.exp(-value));
}
