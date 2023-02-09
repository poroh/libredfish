/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
use reqwest::StatusCode;

use crate::model::InvalidValueError;

#[derive(thiserror::Error, Debug)]
pub enum RedfishError {
    #[error("Network error talking to BMC at {url}. {source}")]
    NetworkError { url: String, source: reqwest::Error },

    #[error("Non-2XX HTTP status at {url}. {source}")]
    HTTPError { url: String, source: reqwest::Error },

    #[error("HTTP {status_code} at {url}. See debug logs for details.")]
    HTTPErrorCode {
        url: String,
        status_code: StatusCode,
    },

    #[error("Could not deserialize response from {url}. Body: {body}. {source}")]
    JsonDeserializeError {
        url: String,
        body: String,
        source: serde_json::Error,
    },

    #[error("Could not serialize request body for {url}. Obj: {object_debug}. {source}")]
    JsonSerializeError {
        url: String,
        object_debug: String,
        source: serde_json::Error,
    },

    #[error("Remote returned empty body")]
    NoContent,

    #[error("No such boot option {0}")]
    MissingBootOption(String),

    #[error("UnnecessaryOperation such as trying to turn on a machine that is already on.")]
    UnnecessaryOperation,

    #[error("Missing key {key} in JSON at {url}")]
    MissingKey { key: String, url: String },

    #[error("Key {key} should be {expected_type} at {url}")]
    InvalidKeyType {
        key: String,
        expected_type: String,
        url: String,
    },

    #[error("Field {field} parse error at {url}: {err}")]
    InvalidValue {
        url: String,
        field: String,
        err: InvalidValueError,
    },
}
