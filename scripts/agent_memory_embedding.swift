import Foundation
import NaturalLanguage

private struct EmbedRequest: Decodable {
    let texts: [String]
}

private struct DescriptionResponse: Encodable {
    let status: String
    let provider: String
    let model: String
    let dimension: Int
}

private struct EmbedResponse: Encodable {
    let status: String
    let dimension: Int
    let vectors: [[Double]]
}

private func writeJSON<T: Encodable>(_ value: T) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    FileHandle.standardOutput.write(try encoder.encode(value))
}

guard let embedding = NLEmbedding.sentenceEmbedding(for: .simplifiedChinese) else {
    FileHandle.standardError.write(Data("simplified Chinese sentence embedding is unavailable\n".utf8))
    exit(2)
}

let argument = CommandLine.arguments.dropFirst().first ?? ""
do {
    switch argument {
    case "--describe":
        try writeJSON(
            DescriptionResponse(
                status: "ok",
                provider: "NaturalLanguage.NLEmbedding",
                model: "sentenceEmbedding:simplifiedChinese",
                dimension: embedding.dimension
            )
        )
    case "--embed":
        let input = FileHandle.standardInput.readDataToEndOfFile()
        let request = try JSONDecoder().decode(EmbedRequest.self, from: input)
        var vectors: [[Double]] = []
        vectors.reserveCapacity(request.texts.count)
        for text in request.texts {
            guard let vector = embedding.vector(for: text), vector.count == embedding.dimension else {
                throw NSError(domain: "AgentMemoryEmbedding", code: 3)
            }
            vectors.append(vector)
        }
        try writeJSON(EmbedResponse(status: "ok", dimension: embedding.dimension, vectors: vectors))
    default:
        FileHandle.standardError.write(Data("expected --describe or --embed\n".utf8))
        exit(64)
    }
} catch {
    FileHandle.standardError.write(Data("embedding request failed\n".utf8))
    exit(3)
}
