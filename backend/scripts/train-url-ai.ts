import fs from "node:fs/promises";
import path from "node:path";
import AdmZip from "adm-zip";
import { parse } from "csv-parse/sync";
import { extractUrlMlFeatures, URL_ML_FEATURES } from "../src/threat/url-ml-features";
import { UrlMlModel } from "../src/threat/url-ml-model";

type Example = {
  url: string;
  label: 0 | 1;
  values: number[];
};

const SAMPLE_SIZE = Number(process.env.AI_TRAINING_SAMPLE_SIZE ?? 300000);
const EPOCHS = Number(process.env.AI_TRAINING_EPOCHS ?? 6);
const LEARNING_RATE = Number(process.env.AI_TRAINING_LEARNING_RATE ?? 0.08);
const L2 = Number(process.env.AI_TRAINING_L2 ?? 0.0002);
const DATASET_DIR = path.resolve(process.cwd(), "datasets");
const MODEL_PATH = path.resolve(process.cwd(), process.env.URL_AI_MODEL_PATH ?? "models/url-phishing-model.json");
const PHISHTANK_URL = phishTankUrl();
const TRANCO_URL = process.env.TRANCO_DATASET_URL ?? "https://tranco-list.eu/top-1m.csv.zip";

async function main() {
  await fs.mkdir(DATASET_DIR, { recursive: true });
  await fs.mkdir(path.dirname(MODEL_PATH), { recursive: true });

  console.log(`Preparing PhishTank positives, target=${SAMPLE_SIZE}`);
  const phishUrls = await loadPhishTankUrls();
  const positiveUrls = selectSample(phishUrls, SAMPLE_SIZE, "phishtank", process.env.AI_TRAINING_ALLOW_SMALLER_PHISHTANK === "true");

  console.log(`Preparing Tranco negatives, target=${SAMPLE_SIZE}`);
  const trancoDomains = await loadTrancoDomains();
  const negativeDomains = selectSample(trancoDomains, SAMPLE_SIZE, "tranco", false);

  const positives = materializeExamples(positiveUrls, 1);
  const negatives = materializeExamples(negativeDomains.map((domain) => `https://${domain}/`), 0);
  const examples = seededShuffle([...positives, ...negatives], 1337);
  const splitIndex = Math.floor(examples.length * 0.8);
  const train = examples.slice(0, splitIndex);
  const test = examples.slice(splitIndex);

  console.log(`Training logistic regression with ${train.length} train and ${test.length} test examples`);
  const weights = new Array(URL_ML_FEATURES.length).fill(0);
  let bias = 0;

  for (let epoch = 0; epoch < EPOCHS; epoch += 1) {
    let loss = 0;
    const shuffled = seededShuffle(train, 2026 + epoch);
    const rate = LEARNING_RATE / (1 + epoch * 0.35);
    for (const example of shuffled) {
      const prediction = sigmoid(dot(weights, example.values) + bias);
      const error = prediction - example.label;
      loss += -(example.label * Math.log(prediction + 1e-9) + (1 - example.label) * Math.log(1 - prediction + 1e-9));
      for (let index = 0; index < weights.length; index += 1) {
        weights[index] -= rate * (error * example.values[index] + L2 * weights[index]);
      }
      bias -= rate * error;
    }
    console.log(`Epoch ${epoch + 1}/${EPOCHS} loss=${(loss / train.length).toFixed(4)}`);
  }

  const metrics = evaluate(test, weights, bias, 0.5);
  const model: UrlMlModel = {
    modelType: "logistic_regression",
    version: 1,
    trainedAt: new Date().toISOString(),
    positiveSource: process.env.PHISHTANK_DATASET_PATH ? `file:${process.env.PHISHTANK_DATASET_PATH}` : PHISHTANK_URL,
    negativeSource: TRANCO_URL,
    positiveCount: positives.length,
    negativeCount: negatives.length,
    featureNames: [...URL_ML_FEATURES],
    weights,
    bias,
    threshold: 0.5,
    metrics
  };

  await fs.writeFile(MODEL_PATH, JSON.stringify(model, null, 2));
  console.log(`Saved URL AI model: ${MODEL_PATH}`);
  console.log(`Metrics: ${JSON.stringify(metrics, null, 2)}`);
}

async function loadPhishTankUrls(): Promise<string[]> {
  const localPath = process.env.PHISHTANK_DATASET_PATH;
  const csv = localPath
    ? await fs.readFile(path.resolve(localPath), "utf8")
    : await downloadText(PHISHTANK_URL, path.join(DATASET_DIR, "phishtank-online-valid.csv"), {
        "user-agent": process.env.PHISHTANK_USER_AGENT ?? "email-soc-phishing-mvp/0.1 security-research-training"
      });
  const rows = parse(csv, { columns: true, skip_empty_lines: true, relax_quotes: true }) as Array<Record<string, string>>;
  return unique(
    rows
      .map((row) => row.url ?? row.URL ?? row.Url)
      .filter((url): url is string => Boolean(url))
      .filter((url) => Boolean(extractUrlMlFeatures(url)))
  );
}

async function loadTrancoDomains(): Promise<string[]> {
  const localPath = process.env.TRANCO_DATASET_PATH;
  let csv: string;
  if (localPath) {
    csv = await readTrancoFile(path.resolve(localPath));
  } else {
    const zipBuffer = await downloadBuffer(TRANCO_URL, path.join(DATASET_DIR, "tranco-top-1m.csv.zip"));
    const zip = new AdmZip(zipBuffer);
    const csvEntry = zip.getEntries().find((entry) => entry.entryName.endsWith(".csv"));
    if (!csvEntry) throw new Error("Tranco zip did not contain a CSV file");
    csv = csvEntry.getData().toString("utf8");
    await fs.writeFile(path.join(DATASET_DIR, "tranco-top-1m.csv"), csv);
  }
  return unique(
    csv
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => line.split(",")[1] ?? line.split(",")[0])
      .map((domain) => domain.trim().toLowerCase())
      .filter((domain) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain))
  );
}

async function readTrancoFile(filePath: string): Promise<string> {
  if (filePath.endsWith(".zip")) {
    const zip = new AdmZip(await fs.readFile(filePath));
    const csvEntry = zip.getEntries().find((entry) => entry.entryName.endsWith(".csv"));
    if (!csvEntry) throw new Error("Tranco zip did not contain a CSV file");
    return csvEntry.getData().toString("utf8");
  }
  return fs.readFile(filePath, "utf8");
}

async function downloadText(url: string, cachePath: string, headers: Record<string, string> = {}): Promise<string> {
  const cached = await tryRead(cachePath);
  if (cached) return cached.toString("utf8");
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`Failed to download ${url}: ${response.status} ${response.statusText}`);
  const text = await response.text();
  await fs.writeFile(cachePath, text);
  return text;
}

async function downloadBuffer(url: string, cachePath: string): Promise<Buffer> {
  const cached = await tryRead(cachePath);
  if (cached) return cached;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Failed to download ${url}: ${response.status} ${response.statusText}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  await fs.writeFile(cachePath, buffer);
  return buffer;
}

async function tryRead(filePath: string): Promise<Buffer | null> {
  try {
    return await fs.readFile(filePath);
  } catch {
    return null;
  }
}

function phishTankUrl(): string {
  if (process.env.PHISHTANK_DATASET_URL) return process.env.PHISHTANK_DATASET_URL;
  if (process.env.PHISHTANK_APP_KEY) {
    return `https://data.phishtank.com/data/${process.env.PHISHTANK_APP_KEY}/online-valid.csv`;
  }
  return "https://data.phishtank.com/data/online-valid.csv";
}

function materializeExamples(urls: string[], label: 0 | 1): Example[] {
  return urls
    .map((url) => {
      const features = extractUrlMlFeatures(url);
      return features ? { url, label, values: features.values } : null;
    })
    .filter((example): example is Example => Boolean(example));
}

function selectSample(values: string[], size: number, label: string, allowSmaller: boolean): string[] {
  if (values.length < size && !allowSmaller) {
    throw new Error(
      `${label} dataset has ${values.length} usable rows, but ${size} were requested. ` +
        `Provide a larger local dataset path or lower AI_TRAINING_SAMPLE_SIZE.`
    );
  }
  const sampleSize = Math.min(size, values.length);
  return seededShuffle(values, label === "phishtank" ? 4242 : 7331).slice(0, sampleSize);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function evaluate(examples: Example[], weights: number[], bias: number, threshold: number) {
  let truePositive = 0;
  let falsePositive = 0;
  let trueNegative = 0;
  let falseNegative = 0;
  for (const example of examples) {
    const probability = sigmoid(dot(weights, example.values) + bias);
    const predicted = probability >= threshold ? 1 : 0;
    if (predicted === 1 && example.label === 1) truePositive += 1;
    if (predicted === 1 && example.label === 0) falsePositive += 1;
    if (predicted === 0 && example.label === 0) trueNegative += 1;
    if (predicted === 0 && example.label === 1) falseNegative += 1;
  }
  const accuracy = (truePositive + trueNegative) / examples.length;
  const precision = truePositive / Math.max(1, truePositive + falsePositive);
  const recall = truePositive / Math.max(1, truePositive + falseNegative);
  const f1 = (2 * precision * recall) / Math.max(1e-9, precision + recall);
  return {
    accuracy: round(accuracy),
    precision: round(precision),
    recall: round(recall),
    f1: round(f1),
    truePositive,
    falsePositive,
    trueNegative,
    falseNegative
  };
}

function dot(weights: number[], values: number[]): number {
  let total = 0;
  for (let index = 0; index < weights.length; index += 1) {
    total += weights[index] * values[index];
  }
  return total;
}

function sigmoid(value: number): number {
  if (value < -35) return 0;
  if (value > 35) return 1;
  return 1 / (1 + Math.exp(-value));
}

function seededShuffle<T>(values: T[], seed: number): T[] {
  const result = [...values];
  const random = mulberry32(seed);
  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(random() * (index + 1));
    [result[index], result[swapIndex]] = [result[swapIndex], result[index]];
  }
  return result;
}

function mulberry32(seed: number): () => number {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let value = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function round(value: number): number {
  return Number(value.toFixed(4));
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
