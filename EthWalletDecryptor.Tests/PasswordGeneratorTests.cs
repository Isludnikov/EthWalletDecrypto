using EthWalletDecryptor.Utils;

namespace EthWalletDecryptor.Tests;

public class PasswordGeneratorTests
{
    [Fact]
    public void BruteForce_SingleCharSingleLen_YieldsOnePassword()
    {
        var results = PasswordGenerator.BruteForce("a", 1, 1).ToList();
        Assert.Equal(["a"], results);
    }

    [Fact]
    public void BruteForce_TwoCharsLen1_YieldsBothInOrder()
    {
        var results = PasswordGenerator.BruteForce("ab", 1, 1).ToList();
        Assert.Equal(["a", "b"], results);
    }

    [Fact]
    public void BruteForce_TwoCharsLen2_YieldsAllCombinations()
    {
        var results = PasswordGenerator.BruteForce("ab", 2, 2).ToList();
        Assert.Equal(["aa", "ab", "ba", "bb"], results);
    }

    [Fact]
    public void BruteForce_MultipleLen_YieldsShorterPasswordsFirst()
    {
        var results = PasswordGenerator.BruteForce("ab", 1, 2).ToList();
        Assert.Equal(["a", "b", "aa", "ab", "ba", "bb"], results);
    }

    [Fact]
    public void BruteForce_Count_MatchesPowerFormula()
    {
        // charset=3, len 1..3: 3^1 + 3^2 + 3^3 = 3 + 9 + 27 = 39
        var count = PasswordGenerator.BruteForce("abc", 1, 3).Count();
        Assert.Equal(39, count);
    }

    [Fact]
    public void BruteForce_AllPasswordsAreUnique()
    {
        var results = PasswordGenerator.BruteForce("abc", 1, 3).ToList();
        Assert.Equal(results.Count, results.Distinct().Count());
    }

    [Fact]
    public void BruteForce_MinGreaterThanMax_YieldsNothing()
    {
        var results = PasswordGenerator.BruteForce("abc", 3, 1).ToList();
        Assert.Empty(results);
    }

    [Fact]
    public void BruteForce_ZeroLength_YieldsEmptyString()
    {
        var results = PasswordGenerator.BruteForce("abc", 0, 0).ToList();
        Assert.Equal([""], results);
    }

    [Fact]
    public void BruteForce_AllPasswordsHaveExpectedLength()
    {
        foreach (var password in PasswordGenerator.BruteForce("abc", 2, 4))
            Assert.InRange(password.Length, 2, 4);
    }

    [Fact]
    public void BruteForce_AllCharsFromCharset()
    {
        const string charset = "x9";
        foreach (var password in PasswordGenerator.BruteForce(charset, 1, 3))
            Assert.All(password, c => Assert.Contains(c, charset));
    }

    [Fact]
    public void BruteForce_SingleLen_CountEqualsCharsetLength()
    {
        var results = PasswordGenerator.BruteForce("abcde", 1, 1).ToList();
        Assert.Equal(5, results.Count);
    }
}
