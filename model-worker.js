/**
 * model-worker.js
 * ================
 * Web Worker: loads DistilBERT (via Transformers.js / ONNX) and
 * responds to classification requests from the main thread.
 *
 * Messages IN  → { type: 'classify', text: string, id: number }
 * Messages OUT → { type: 'ready' }
 *              → { type: 'result',  id, label, score, confidence }
 *              → { type: 'error',   id, message }
 *              → { type: 'progress', message }
 */

import { pipeline, env } from 'https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.5.0';

/* ── Transformers.js config ── */
// Use remote model from Hugging Face CDN (first load downloads & caches)
env.allowLocalModels  = false;
env.useBrowserCache   = true;   // cache in IndexedDB across sessions

const MODEL_ID = 'Xenova/distilbert-base-uncased-finetuned-sst-2-english';

let classifier = null;

/* ── Boot: load the model ── */
async function loadModel() {
  try {
    self.postMessage({ type: 'progress', message: 'Downloading DistilBERT model…' });

    classifier = await pipeline('text-classification', MODEL_ID, {
      // quantized=true uses int8-quantized weights (~68 MB → ~17 MB)
      quantized: true,
      progress_callback: (progressInfo) => {
        if (progressInfo.status === 'downloading') {
          const pct = progressInfo.progress != null
            ? ` (${Math.round(progressInfo.progress)}%)`
            : '';
          self.postMessage({
            type: 'progress',
            message: `Downloading model weights${pct}…`,
          });
        } else if (progressInfo.status === 'loading') {
          self.postMessage({ type: 'progress', message: 'Loading model into memory…' });
        }
      },
    });

    self.postMessage({ type: 'ready' });
  } catch (err) {
    self.postMessage({ type: 'error', id: -1, message: err.message });
  }
}

/* ── Message handler ── */
self.addEventListener('message', async (event) => {
  const { type, text, id } = event.data;

  if (type !== 'classify') return;

  if (!classifier) {
    self.postMessage({ type: 'error', id, message: 'Model not loaded yet.' });
    return;
  }

  try {
    // Truncate to first 512 tokens worth of characters (~1800 chars) to stay within model limits
    const truncated = text.slice(0, 1800);
    const [result] = await classifier(truncated);

    /*
     * SST-2 labels: POSITIVE / NEGATIVE
     *
     * Mapping rationale:
     *  - Phishing emails use alarming, negative-sentiment language
     *    ("your account has been suspended", "act now or lose access")
     *  - We treat NEGATIVE confidence as the AI phishing signal (0–1)
     *  - Safe, neutral, business emails tend to score POSITIVE
     */
    const isNegative = result.label === 'NEGATIVE';
    const rawConf    = result.score; // 0–1 confidence for the predicted label

    // Phishing confidence: high when model says NEGATIVE with high confidence
    const phishingConf = isNegative ? rawConf : (1 - rawConf);

    self.postMessage({
      type:         'result',
      id,
      label:        result.label,
      score:        result.score,
      // phishingConf is the key value: 0 = definitely safe, 1 = definitely phishing
      phishingConf,
    });
  } catch (err) {
    self.postMessage({ type: 'error', id, message: err.message });
  }
});

/* ── Start loading immediately on worker spawn ── */
loadModel();
